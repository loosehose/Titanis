# Snaffler
  Hunt for credentials and secrets on SMB shares

## Synopsis
```
Snaffler <subcommand>
```

### Subcommands

|Command|Description|
|-|-|
|[scan](#snaffler-scan)|Scan SMB shares for credentials and secrets|
|[shares](#snaffler-shares)|Enumerate shares on target hosts|
|[rules](#snaffler-rules)|List loaded classification rules|


  For help on a subcommand, use `Snaffler <subcommand> -h`
# Snaffler scan
  Scan SMB shares for credentials and secrets

## Synopsis
```
Snaffler scan [options] <host1,host2,...>
```

## Parameters

|Name|Aliases|Value|Description|
|-|-|-|-|
|&lt;Targets&gt;||&lt;String[]&gt;|Target hosts to scan (comma-separated)|


## Options


### Target Discovery

|Name|Aliases|Value|Description|
|-|-|-|-|
|-T, -TargetFile||&lt;String&gt;|File containing target hosts (one per line)|
|-s, -Shares||&lt;String[]&gt;|Direct UNC share paths to scan|
|-d, -DomainController||&lt;String&gt;|Domain controller for LDAP computer discovery|
|    -LdapPort||&lt;Int32&gt;|LDAP port (default: 389, use 636 for LDAPS)|


### Scanning

|Name|Aliases|Value|Description|
|-|-|-|-|
|    -MaxSizeToGrep||&lt;Int64&gt;|Maximum file size in bytes to scan for content (default: 1000000)|
|    -ContextBytes||&lt;Int32&gt;|Number of context bytes to show around matches (default: 200)|
|    -MaxDepth||&lt;Int32&gt;|Maximum directory depth (-1 = unlimited, default: -1)|
|    -InterestLevel||&lt;Int32&gt;|Minimum interest level: 0=all, 1=Yellow+, 2=Red+, 3=Black only (default: 0)|
|    -NoContent||&lt;SwitchParam&gt;|Only scan file names, skip content scanning|
|    -ScanSysvol||&lt;SwitchParam&gt;|Scan SYSVOL share (default: true)|
|    -ScanNetlogon||&lt;SwitchParam&gt;|Scan NETLOGON share (default: true)|


### Parallelism

|Name|Aliases|Value|Description|
|-|-|-|-|
|    -MaxHostWorkers||&lt;Int32&gt;|Maximum number of hosts to scan in parallel (default: 10)|
|    -MaxShareWorkers||&lt;Int32&gt;|Maximum number of shares to scan in parallel per host (default: 10)|
|    -MaxFileWorkers||&lt;Int32&gt;|Maximum number of files to process in parallel (default: 40)|


### Rules

|Name|Aliases|Value|Description|
|-|-|-|-|
|-r, -RulePath||&lt;String&gt;|Path to directory containing custom TOML rules|


### Output

|Name|Aliases|Value|Description|
|-|-|-|-|
|    -SnafflePath||&lt;String&gt;|Download matching files to the specified path|
|    -MaxSizeToSnaffle||&lt;Int64&gt;|Maximum file size to download (default: 10000000)|
|    -ConsoleOutputStyle|-OutputStyle|&lt;OutputStyle&gt;|Determines the output style|
||||**Possible values:**|
||||  Freeform|
||||  Raw|
||||  Table|
||||  List|
||||  Csv|
||||  Tsv|
||||  Json|
|    -LogLevel||&lt;LogMessageSeverity&gt;|Sets the lowest level of messages to log|
||||**Possible values:**|
||||  Debug|
||||  Diagnostic|
||||  Verbose|
||||  Info|
||||  Warning|
||||  Error|
||||  Critical|
|    -ConsoleLogFormat|-LogFormat|&lt;LogFormat&gt;|Sets the format of log messages written to the console|
||||  Default: 0|
||||**Possible values:**|
||||  Text|
||||  TextWithTimestamp|
||||  Json|
|    -Verbose|-V|&lt;SwitchParam&gt;|Prints verbose messages|
|    -Diagnostic|-vv|&lt;SwitchParam&gt;|Prints diagnostic messages|
|    -HumanReadable||&lt;SwitchParam&gt;|Formats file sizes as human-readable values|


### Authentication

|Name|Aliases|Value|Description|
|-|-|-|-|
|    -Anonymous||&lt;SwitchParam&gt;|Uses anonymous login|
|    -UserName|-u|&lt;UserPrincipalName&gt;|User name to authenticate with, not including the domain|
|    -UserDomain|-ud|&lt;String&gt;|Domain of user to authenticate with|
|    -Password|-p|&lt;String&gt;|Password to authenticate with|
|    -NtlmHash||&lt;hexadecimal hash&gt;|NTLM hash for NTLM authentication|


### Authentication (Kerberos)

|Name|Aliases|Value|Description|
|-|-|-|-|
|    -AesKey||&lt;HexString&gt;|AES key (128 or 256)|
|    -DesKey||&lt;HexString&gt;|DES key|
|    -Tgt||&lt;String&gt;|Name of file containing a ticket-granting ticket (.kirbi or ccache)|
|    -Tickets||&lt;String[]&gt;|Name of file containing service tickets (.kirbi or ccache)|
|    -TicketCache||&lt;String&gt;|Name of ticket cache file|
|-K, -Kdc||&lt;host-or-ip:port&gt;|KDC endpoint|
|    -S4UserName||&lt;UserPrincipalName&gt;|Name of user to impersonate with S4U|
|    -S4UserCert||&lt;String&gt;|Name of file containing a certificate of a user to impersonate with S4U|
|    -S4ProxyService||&lt;SecurityPrincipalName&gt;|Name of service to proxy through|


### Authentication (NTLM)

|Name|Aliases|Value|Description|
|-|-|-|-|
|    -Workstation|-w|&lt;String&gt;|Name of workstation to send with NTLM authentication|
|    -NtlmVersion||&lt;Version&gt;|NTLM version number (a.b.c.d)|


### Connection

|Name|Aliases|Value|Description|
|-|-|-|-|
|    -HostAddress|-ha|&lt;String[]&gt;|Network address(es) of the server|
|    -UseTcp6Only|-6|&lt;SwitchParam&gt;|Only use TCP over IPv6 endpoint|
|    -UseTcp4Only|-4|&lt;SwitchParam&gt;|Only use TCP over IPv4 endpoint|
|    -Socks5||&lt;host-or-ip:port&gt;|End point of SOCKS 5 server to use|
|    -Dialects||&lt;Smb2Dialect[]&gt;|List of SMB2 dialects to negotiate|
||||**Possible values:**|
||||  Smb2_0_2|
||||  Smb2_1|
||||  Smb3_0|
||||  Smb3_0_2|
||||  Smb3_1_1|
|    -RequireSigning|-signreq|&lt;SwitchParam&gt;|Requires packets to be signed|
|    -EncryptSmb||&lt;SwitchParam&gt;|Requires an encrypted connection|


## Details

The `scan` command discovers and scans SMB shares for credentials, secrets, and other
sensitive files. It uses a rule-based classification engine ported from
[Snaffler](https://github.com/SnaffCon/Snaffler).

### Target Discovery

Targets can be supplied in three ways:

1. **Positional arguments** - hostnames or IP addresses directly on the command line
2. **Target file** (`-T`) - a text file with one host per line
3. **LDAP discovery** (`-d`) - queries a domain controller for computer accounts

When using LDAP discovery, Snaffler queries the domain controller for all enabled
computer accounts and scans each one for accessible shares.

### Classification Pipeline

Files are processed through a multi-stage pipeline:

1. **Share enumeration** - shares are classified (e.g., SYSVOL, NETLOGON, admin shares)
2. **Directory enumeration** - directories are checked against discard/keep rules
3. **File enumeration** - file names and extensions are matched against rules
4. **Content scanning** - file contents are searched using regex patterns
5. **Post-match** - additional filtering on matched results

### Triage Levels

Matches are classified by severity:

|Level|Description|
|-|-|
|Black|Critical - active credentials, private keys with passwords|
|Red|High - likely credentials, connection strings|
|Yellow|Medium - configuration files, interesting scripts|
|Green|Low - potentially interesting files|

### Output Format

The default output format produces one line per match in the original Snaffler format:

```
{Triage}<Rule|RW|Pattern|Size|Timestamp>(Context) Path
```

Where `R` and `W` indicate whether the file is readable and writable.

### Custom Rules

Rules are defined in TOML files. Use `-RulePath` to load rules from a directory
instead of the built-in defaults. Use `Snaffler rules` to inspect loaded rules.

## Examples

### Scan a single host with password authentication
```
Snaffler scan dc01.corp.local -u admin -ud CORP -p 'Password123!'
```

### Scan multiple hosts
```
Snaffler scan dc01.corp.local,fs01.corp.local -u admin -ud CORP -p 'Password123!'
```

### Scan from a target file
```
Snaffler scan -T targets.txt -u admin -ud CORP -p 'Password123!'
```

### Scan specific shares
```
Snaffler scan -s \\dc01\SYSVOL -s \\dc01\NETLOGON -u admin -ud CORP -p 'Password123!'
```

### Discover targets via LDAP
```
Snaffler scan -d dc01.corp.local -u admin -ud CORP -p 'Password123!'
```

### Use LDAPS (port 636)
```
Snaffler scan -d dc01.corp.local -LdapPort 636 -u admin -ud CORP -p 'Password123!'
```

### Authenticate with an NTLM hash (pass-the-hash)
```
Snaffler scan dc01.corp.local -u admin -ud CORP -NtlmHash aad3b435b51404eeaad3b435b51404ee
```

### Authenticate with a Kerberos TGT
```
Snaffler scan dc01.corp.local -Tgt admin.kirbi
```

### Only show high-severity results (Red and Black)
```
Snaffler scan dc01.corp.local -u admin -ud CORP -p 'Password123!' -InterestLevel 2
```

### Skip content scanning (file names only)
```
Snaffler scan dc01.corp.local -u admin -ud CORP -p 'Password123!' -NoContent
```

### Download matching files
```
Snaffler scan dc01.corp.local -u admin -ud CORP -p 'Password123!' -SnafflePath ./loot/
```

### Use custom rules
```
Snaffler scan dc01.corp.local -u admin -ud CORP -p 'Password123!' -RulePath ./my-rules/
```

### Scan through a SOCKS5 proxy
```
Snaffler scan dc01.corp.local -u admin -ud CORP -p 'Password123!' -Socks5 127.0.0.1:1080
```

### Output as JSON
```
Snaffler scan dc01.corp.local -u admin -ud CORP -p 'Password123!' -OutputStyle Json
```

# Snaffler shares
  Enumerate shares on target hosts

## Synopsis
```
Snaffler shares [options] <host1,host2,...>
```

## Parameters

|Name|Aliases|Value|Description|
|-|-|-|-|
|&lt;Targets&gt;||&lt;String[]&gt;|Target hosts to enumerate (comma-separated)|


## Options

|Name|Aliases|Value|Description|
|-|-|-|-|
|-T, -TargetFile||&lt;String&gt;|File containing target hosts (one per line)|


### Authentication

|Name|Aliases|Value|Description|
|-|-|-|-|
|    -Anonymous||&lt;SwitchParam&gt;|Uses anonymous login|
|    -UserName|-u|&lt;UserPrincipalName&gt;|User name to authenticate with, not including the domain|
|    -UserDomain|-ud|&lt;String&gt;|Domain of user to authenticate with|
|    -Password|-p|&lt;String&gt;|Password to authenticate with|
|    -NtlmHash||&lt;hexadecimal hash&gt;|NTLM hash for NTLM authentication|


### Connection

|Name|Aliases|Value|Description|
|-|-|-|-|
|    -HostAddress|-ha|&lt;String[]&gt;|Network address(es) of the server|
|    -UseTcp6Only|-6|&lt;SwitchParam&gt;|Only use TCP over IPv6 endpoint|
|    -UseTcp4Only|-4|&lt;SwitchParam&gt;|Only use TCP over IPv4 endpoint|
|    -Socks5||&lt;host-or-ip:port&gt;|End point of SOCKS 5 server to use|


### Output

|Name|Aliases|Value|Description|
|-|-|-|-|
|    -ConsoleOutputStyle|-OutputStyle|&lt;OutputStyle&gt;|Determines the output style|
||||**Possible values:**|
||||  Freeform|
||||  Raw|
||||  Table|
||||  List|
||||  Csv|
||||  Tsv|
||||  Json|
|    -LogLevel||&lt;LogMessageSeverity&gt;|Sets the lowest level of messages to log|
|    -Verbose|-V|&lt;SwitchParam&gt;|Prints verbose messages|


## Details

The `shares` command enumerates shares on one or more target hosts without performing
any content scanning. It reports each share's path, description, and whether the root
is readable — useful for reconnaissance before a full scan.

## Examples

### List shares on a host
```
Snaffler shares dc01.corp.local -u admin -ud CORP -p 'Password123!'
```

### List shares on multiple hosts from a file
```
Snaffler shares -T targets.txt -u admin -ud CORP -p 'Password123!'
```

# Snaffler rules
  List loaded classification rules

## Synopsis
```
Snaffler rules [options]
```

## Options

|Name|Aliases|Value|Description|
|-|-|-|-|
|-r, -RulePath||&lt;String&gt;|Path to directory containing custom TOML rules|
|    -Scope||&lt;EnumerationScope&gt;|Filter rules by scope|
||||**Possible values:**|
||||  ShareEnumeration|
||||  DirectoryEnumeration|
||||  FileEnumeration|
||||  ContentsEnumeration|
||||  PostMatch|
|    -Action||&lt;MatchAction&gt;|Filter rules by action|
||||**Possible values:**|
||||  Discard|
||||  SendToNextScope|
||||  Snaffle|
||||  Relay|
||||  CheckForKeys|
||||  EnterArchive|
|    -MinTriage||&lt;Triage&gt;|Filter rules by minimum triage level|
||||**Possible values:**|
||||  Black|
||||  Red|
||||  Yellow|
||||  Green|
||||  Gray|
|    -ShowPatterns||&lt;SwitchParam&gt;|Show patterns for each rule|


## Details

The `rules` command displays the classification rules that Snaffler uses to identify
interesting files. By default it loads the embedded rule set; use `-RulePath` to
inspect custom rules. Filters can narrow the output by scope, action, or triage level.

## Examples

### List all embedded rules
```
Snaffler rules
```

### List only content-scanning rules
```
Snaffler rules -Scope ContentsEnumeration
```

### List rules that produce Black (critical) matches
```
Snaffler rules -MinTriage Black
```

### Inspect custom rules with patterns
```
Snaffler rules -RulePath ./my-rules/ -ShowPatterns -V
```
