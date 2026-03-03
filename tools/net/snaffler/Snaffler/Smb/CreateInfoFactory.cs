using Titanis.Smb2;
using Titanis.Smb2.Pdus;
using FileAttributes = Titanis.Winterop.FileAttributes;

namespace Titanis.Snaffler.Cli.Smb;

/// <summary>
/// Factory for SMB2 create info structures.
/// Centralizes creation to avoid duplication and ensure consistency.
/// </summary>
internal static class CreateInfoFactory
{
    /// <summary>
    /// Creates info for opening a directory with read-only access.
    /// </summary>
    public static Smb2CreateInfo OpenDirectoryReadOnly() => new()
    {
        CreateDisposition = Smb2CreateDisposition.Open,
        Priority = Smb2Priority.OpenDir,
        DesiredAccess = (uint)Smb2FileAccessRights.DefaultOpenDirAccess,
        ShareAccess = Smb2ShareAccess.DefaultDirShare,
        FileAttributes = FileAttributes.None,
        CreateOptions = Smb2FileCreateOptions.Directory | Smb2FileCreateOptions.SynchronousIoNonalert,
        ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
        RequestMaximalAccess = true,
        QueryOnDiskId = true,
    };

    /// <summary>
    /// Creates info for opening a file with read-only access.
    /// </summary>
    public static Smb2CreateInfo OpenFileReadOnly() => new()
    {
        CreateDisposition = Smb2CreateDisposition.Open,
        DesiredAccess = (uint)(Smb2FileAccessRights.ReadData | Smb2FileAccessRights.ReadAttributes | Smb2FileAccessRights.Synchronize),
        ShareAccess = Smb2ShareAccess.Read,
        ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
        CreateOptions = Smb2FileCreateOptions.NonDirectory | Smb2FileCreateOptions.SynchronousIoNonalert,
        FileAttributes = FileAttributes.Normal
    };
}
