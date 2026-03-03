using System.ComponentModel;
using Titanis.Cli;

namespace Titanis.Snaffler.Cli;

/// <summary>
/// Snaffler - Hunt for credentials and secrets on SMB shares.
/// </summary>
/// <remarks>
/// This is a port of Snaffler (https://github.com/SnaffCon/Snaffler) to Titanis,
/// providing cross-platform credential hunting using Titanis's SMB2/3 implementation.
/// </remarks>
[Description("Hunt for credentials and secrets on SMB shares")]
[Subcommand("scan", typeof(ScanCommand))]
[Subcommand("shares", typeof(ListSharesCommand))]
[Subcommand("rules", typeof(ListRulesCommand))]
internal class Program : MultiCommand
{
    static int Main(string[] args)
        => RunProgramAsync<Program>(args);
}
