using System.Buffers;
using System.Collections.Concurrent;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using Titanis.Asn1.Serialization;
using Titanis.IO;
using Titanis.Net.Ldap.Protocol;
using Titanis.Net.Ldap.Protocol.Controls;
using Titanis.Net.Ldap.Protocol.Requests;
using Titanis.Net.Ldap.Protocol.Responses;
using Titanis.Net.Ldap.Protocol.Search;

namespace Titanis.Net.Ldap.Client;

/// <summary>
/// Options for LDAP connections.
/// </summary>
public sealed class LdapConnectionOptions
{
    /// <summary>
    /// Gets or sets the server hostname.
    /// </summary>
    public string Host { get; set; } = "";

    /// <summary>
    /// Gets or sets the server port (default: 389, or 636 for LDAPS).
    /// </summary>
    public int Port { get; set; } = 389;

    /// <summary>
    /// Gets or sets whether to use SSL/TLS.
    /// </summary>
    public bool UseSsl { get; set; }

    /// <summary>
    /// Gets or sets the connection timeout.
    /// </summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets or sets the operation timeout.
    /// </summary>
    public TimeSpan OperationTimeout { get; set; } = TimeSpan.FromSeconds(60);
}

/// <summary>
/// LDAP connection providing message-level protocol operations.
/// </summary>
public sealed class LdapConnection : IAsyncDisposable
{
    private readonly LdapConnectionOptions _options;
    private TcpClient? _tcpClient;
    private Stream? _stream;
    private SslStream? _sslStream;
    private readonly ConcurrentDictionary<int, TaskCompletionSource<LdapMessage>> _pendingRequests = new();
    private readonly ConcurrentDictionary<int, Channel<LdapMessage>> _searchChannels = new();
    private int _nextMessageId;
    private Task? _readTask;
    private CancellationTokenSource? _readCts;
    private bool _disposed;

    /// <summary>
    /// Gets whether the connection is established.
    /// </summary>
    public bool IsConnected => _tcpClient?.Connected ?? false;

    /// <summary>
    /// Initializes a new instance of the <see cref="LdapConnection"/> class.
    /// </summary>
    public LdapConnection(LdapConnectionOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Connects to the LDAP server.
    /// </summary>
    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(LdapConnection));
        if (IsConnected) throw new InvalidOperationException("Already connected");

        _tcpClient = new TcpClient();

        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(_options.ConnectTimeout);

        await _tcpClient.ConnectAsync(_options.Host, _options.Port, connectCts.Token).ConfigureAwait(false);
        Stream baseStream = _tcpClient.GetStream();

        if (_options.UseSsl)
        {
            _sslStream = new SslStream(baseStream, leaveInnerStreamOpen: false, (sender, cert, chain, errors) => true);
            await _sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = _options.Host,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
            }, connectCts.Token).ConfigureAwait(false);
            baseStream = _sslStream;
        }

        _stream = baseStream;

        // Start the read loop
        _readCts = new CancellationTokenSource();
        _readTask = ReadLoopAsync(_readCts.Token);
    }

    /// <summary>
    /// Sends a message and waits for a single response.
    /// </summary>
    public async Task<LdapMessage> SendAsync(ILdapProtocolOp request, IReadOnlyList<LdapControl>? controls = null, CancellationToken cancellationToken = default)
    {
        if (!IsConnected) throw new InvalidOperationException("Not connected");

        var messageId = Interlocked.Increment(ref _nextMessageId);
        var tcs = new TaskCompletionSource<LdapMessage>(TaskCreationOptions.RunContinuationsAsynchronously);

        _pendingRequests[messageId] = tcs;

        try
        {
            var message = new LdapMessage
            {
                MessageId = messageId,
                ProtocolOp = request,
                Controls = controls
            };

            await SendMessageAsync(message, cancellationToken).ConfigureAwait(false);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_options.OperationTimeout);

            return await tcs.Task.WaitAsync(timeoutCts.Token).ConfigureAwait(false);
        }
        finally
        {
            _pendingRequests.TryRemove(messageId, out _);
        }
    }

    /// <summary>
    /// Sends a search request and returns results as an async enumerable.
    /// </summary>
    public async IAsyncEnumerable<LdapMessage> SendSearchAsync(
        SearchRequest request,
        IReadOnlyList<LdapControl>? controls = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (!IsConnected) throw new InvalidOperationException("Not connected");

        var messageId = Interlocked.Increment(ref _nextMessageId);
        var channel = new Channel<LdapMessage>();

        _searchChannels[messageId] = channel;

        try
        {
            var message = new LdapMessage
            {
                MessageId = messageId,
                ProtocolOp = request,
                Controls = controls
            };

            await SendMessageAsync(message, cancellationToken).ConfigureAwait(false);

            while (true)
            {
                var response = await channel.ReadAsync(cancellationToken).ConfigureAwait(false);
                yield return response;

                if (response.ProtocolOp is SearchResultDone)
                    break;
            }
        }
        finally
        {
            _searchChannels.TryRemove(messageId, out _);
        }
    }

    private async Task SendMessageAsync(LdapMessage message, CancellationToken cancellationToken)
    {
        var bytes = message.Encode();
        await _stream!.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }

    private async Task ReadLoopAsync(CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(65536);

        try
        {
            var reader = new LdapMessageReader(_stream!);

            while (!cancellationToken.IsCancellationRequested)
            {
                LdapMessage? message;
                try
                {
                    message = await reader.ReadMessageAsync(cancellationToken).ConfigureAwait(false);
                    if (message == null)
                        break; // Connection closed
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch
                {
                    // Connection error
                    break;
                }

                DispatchMessage(message);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            CompleteAllPending();
        }
    }

    private void DispatchMessage(LdapMessage message)
    {
        // Check if this is a search response
        if (_searchChannels.TryGetValue(message.MessageId, out var channel))
        {
            channel.Write(message);
            return;
        }

        // Check if this is a regular response
        if (_pendingRequests.TryRemove(message.MessageId, out var tcs))
        {
            tcs.SetResult(message);
        }
    }

    private void CompleteAllPending()
    {
        foreach (var kvp in _pendingRequests)
        {
            kvp.Value.TrySetException(new LdapException(LdapResultCode.Unavailable, "Connection closed"));
        }
        _pendingRequests.Clear();

        foreach (var kvp in _searchChannels)
        {
            kvp.Value.Complete();
        }
        _searchChannels.Clear();
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        _readCts?.Cancel();

        if (_readTask != null)
        {
            try { await _readTask.ConfigureAwait(false); } catch { }
        }

        _sslStream?.Dispose();
        _stream?.Dispose();
        _tcpClient?.Dispose();

        _readCts?.Dispose();
    }

    /// <summary>
    /// Simple async channel for search results.
    /// </summary>
    private sealed class Channel<T>
    {
        private readonly ConcurrentQueue<T> _queue = new();
        private readonly SemaphoreSlim _semaphore = new(0);
        private bool _completed;

        public void Write(T item)
        {
            _queue.Enqueue(item);
            _semaphore.Release();
        }

        public void Complete()
        {
            _completed = true;
            _semaphore.Release();
        }

        public async ValueTask<T> ReadAsync(CancellationToken cancellationToken)
        {
            await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            if (_queue.TryDequeue(out var item))
                return item;

            if (_completed)
                throw new InvalidOperationException("Channel completed");

            throw new InvalidOperationException("Unexpected channel state");
        }
    }
}

/// <summary>
/// Helper class to read LDAP messages from a stream.
/// </summary>
internal sealed class LdapMessageReader
{
    private readonly Stream _stream;
    private readonly byte[] _headerBuffer = new byte[16];

    public LdapMessageReader(Stream stream)
    {
        _stream = stream;
    }

    public async Task<LdapMessage?> ReadMessageAsync(CancellationToken cancellationToken)
    {
        // Read the tag and length
        var firstByte = await ReadByteAsync(cancellationToken).ConfigureAwait(false);
        if (firstByte < 0)
            return null;

        // This should be a SEQUENCE tag (0x30)
        if (firstByte != 0x30)
            throw new InvalidDataException($"Expected SEQUENCE tag, got 0x{firstByte:X2}");

        // Read the length
        var length = await ReadLengthAsync(cancellationToken).ConfigureAwait(false);

        // Read the message content
        var content = new byte[length + 2 + GetLengthOfLength(length)];
        content[0] = (byte)firstByte;

        var offset = 1;
        offset += EncodeLengthTo(content.AsSpan(offset), length);

        var remaining = length;
        while (remaining > 0)
        {
            var read = await _stream.ReadAsync(content.AsMemory(offset, remaining), cancellationToken).ConfigureAwait(false);
            if (read == 0)
                throw new EndOfStreamException();
            offset += read;
            remaining -= read;
        }

        return LdapMessage.Decode(content);
    }

    private async ValueTask<int> ReadByteAsync(CancellationToken cancellationToken)
    {
        var read = await _stream.ReadAsync(_headerBuffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
        return read == 0 ? -1 : _headerBuffer[0];
    }

    private async ValueTask<int> ReadLengthAsync(CancellationToken cancellationToken)
    {
        var firstByte = await ReadByteAsync(cancellationToken).ConfigureAwait(false);
        if (firstByte < 0)
            throw new EndOfStreamException();

        if (firstByte < 0x80)
            return firstByte;

        if (firstByte == 0x80)
            throw new NotSupportedException("Indefinite length encoding not supported");

        var lengthBytes = firstByte & 0x7F;
        if (lengthBytes > 4)
            throw new InvalidDataException("Length too large");

        var bytesRead = await _stream.ReadAsync(_headerBuffer.AsMemory(0, lengthBytes), cancellationToken).ConfigureAwait(false);
        if (bytesRead < lengthBytes)
            throw new EndOfStreamException();

        int length = 0;
        for (int i = 0; i < lengthBytes; i++)
        {
            length = (length << 8) | _headerBuffer[i];
        }

        return length;
    }

    private static int GetLengthOfLength(int length)
    {
        if (length < 0x80) return 1;
        if (length < 0x100) return 2;
        if (length < 0x10000) return 3;
        if (length < 0x1000000) return 4;
        return 5;
    }

    private static int EncodeLengthTo(Span<byte> buffer, int length)
    {
        if (length < 0x80)
        {
            buffer[0] = (byte)length;
            return 1;
        }

        var lengthBytes = GetLengthOfLength(length) - 1;
        buffer[0] = (byte)(0x80 | lengthBytes);

        for (int i = lengthBytes; i > 0; i--)
        {
            buffer[i] = (byte)length;
            length >>= 8;
        }

        return lengthBytes + 1;
    }
}
