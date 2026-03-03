# Snaffler Usage Guide

Hunt for credentials and secrets on SMB shares.

```
Snaffler <subcommand>
```

|Subcommand|Description|
|-|-|
|[scan](#scan)|Scan SMB shares for credentials and secrets|
|[shares](#shares)|Enumerate shares on target hosts|
|[rules](#rules)|List loaded classification rules|

For help on any subcommand: `Snaffler <subcommand> -h`

For the full parameter reference, see [Snaffler.md](Snaffler.md).

---

## scan

Walks SMB shares, classifies files using TOML rules, and reports matches by severity.

```
Snaffler scan [options] <host1,host2,...>
```

### Target Discovery

Targets can be provided three ways:

```
# Positional -- hostnames or IPs
Snaffler scan dc01.corp.local,fs01.corp.local -u admin -ud CORP -p 'Pass123!'

# Target file -- one host per line
Snaffler scan -T targets.txt -u admin -ud CORP -p 'Pass123!'

# LDAP discovery -- queries DC for all computer accounts
Snaffler scan -d dc01.corp.local -u admin -ud CORP -p 'Pass123!'
```

You can also scan specific UNC paths directly:

```
Snaffler scan -s \\dc01\SYSVOL -s \\dc01\NETLOGON -u admin -ud CORP -p 'Pass123!'
```

### Authentication

Password, pass-the-hash, and Kerberos are all supported. These work the same as all other Titanis tools.

```
# Password
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!'

# NTLM hash (pass-the-hash)
Snaffler scan dc01 -u admin -ud CORP -NtlmHash aad3b435b51404eeaad3b435b51404ee

# Kerberos TGT
Snaffler scan dc01 -Tgt admin.kirbi

# Kerberos with ticket cache
Snaffler scan dc01 -TicketCache admin.ccache

# S4U impersonation
Snaffler scan dc01 -u svc_account -ud CORP -p 'Pass123!' -S4UserName targetuser -Kdc dc01.corp.local
```

### Scanning Options

```
# Limit directory depth
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -MaxDepth 5

# Skip content scanning (file names and extensions only -- much faster)
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -NoContent

# Only show Red and Black severity results
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -InterestLevel 2

# Increase max file size for content scanning (default: 1MB)
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -MaxSizeToGrep 5000000
```

### Downloading Matches

```
# Download matching files to a local directory
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -SnafflePath ./loot/

# Limit download size (default: 10MB)
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -SnafflePath ./loot/ -MaxSizeToSnaffle 50000000
```

### Output Formats

```
# Default one-line-per-match format
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!'

# JSON output
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -OutputStyle Json

# CSV output
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -OutputStyle Csv

# Timestamped log format
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -ConsoleLogFormat TextWithTimestamp

# Write to file with timestamps
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -o snaffler.log -ConsoleLogFormat TextWithTimestamp
```

### Parallelism

```
# Tune concurrency (defaults: 10 hosts, 10 shares/host, 40 files)
Snaffler scan -T targets.txt -u admin -ud CORP -p 'Pass123!' -MaxHostWorkers 20 -MaxShareWorkers 5 -MaxFileWorkers 80
```

### Connection Options

```
# Through a SOCKS5 proxy
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -Socks5 127.0.0.1:1080

# Force IPv4 only
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -4

# Require SMB signing
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -RequireSigning

# Require SMB encryption
Snaffler scan dc01 -u admin -ud CORP -p 'Pass123!' -EncryptSmb
```

### Triage Levels

Matches are classified by severity:

|Level|Color|Description|
|-|-|-|
|Black|Critical|Active credentials, private keys with passwords|
|Red|High|Likely credentials, connection strings|
|Yellow|Medium|Configuration files, interesting scripts|
|Green|Low|Potentially interesting files|

Default output format per match:

```
{Triage}<Rule|RW|Pattern|Size|Timestamp>(Context) \\host\share\path
```

`R`/`W` indicate whether the file is readable/writable.

---

## shares

Enumerate shares without scanning content. Useful for reconnaissance before a full scan.

```
Snaffler shares [options] <host1,host2,...>
```

```
# Single host
Snaffler shares dc01.corp.local -u admin -ud CORP -p 'Pass123!'

# Multiple hosts from file
Snaffler shares -T targets.txt -u admin -ud CORP -p 'Pass123!'

# JSON output
Snaffler shares dc01.corp.local -u admin -ud CORP -p 'Pass123!' -OutputStyle Json
```

Reports each share's path, description, and whether the root is readable.

---

## rules

Display the classification rules Snaffler uses to identify interesting files.

```
Snaffler rules [options]
```

```
# List all embedded rules
Snaffler rules

# Filter by scope
Snaffler rules -Scope ContentsEnumeration

# Filter by triage level
Snaffler rules -MinTriage Red

# Filter by action
Snaffler rules -Action Snaffle

# Show regex patterns
Snaffler rules -ShowPatterns -V

# Inspect custom rules
Snaffler rules -RulePath ./my-rules/ -ShowPatterns
```

### Rule Scopes

|Scope|Description|
|-|-|
|ShareEnumeration|Applied to share names|
|DirectoryEnumeration|Applied to directory paths|
|FileEnumeration|Applied to file names and extensions|
|ContentsEnumeration|Applied to file contents (regex)|
|PostMatch|Applied after initial match for filtering|

### Rule Actions

|Action|Description|
|-|-|
|Discard|Skip this item|
|SendToNextScope|Pass to the next pipeline stage|
|Snaffle|Report as a match|
|Relay|Pass file contents to content scanning|
|CheckForKeys|Check for private key material|
|EnterArchive|Enter archive files|

### Custom Rules

Rules are TOML files loaded from a directory. Use `-RulePath` to point at your own rules instead of the defaults. See the built-in rules at `tools/net/snaffler/Snaffler/Rules/DefaultRules/` for the format.
