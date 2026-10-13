# Windows and Active Directory — tool recognition reference

A quick reference for recognising commonly encountered security tools in endpoint, PowerShell and authentication telemetry. The tools below have legitimate administration or security-testing uses; their presence alone does not establish malicious activity. Confirm the account, process tree, authorisation, network context, and what the activity achieved.

## Enumeration

| Tool | Purpose | Useful indicators |
|---|---|---|
| **BloodHound** | Visualises AD relationships and potential attack paths | BloodHound collection artefacts and related analysis data |
| **SharpHound / Invoke-BloodHound** | Gathers group, local admin, session, trust and ACL relationships for BloodHound | `Invoke-BloodHound`, `SharpHound`, collection-method parameters; PowerShell 4104 or Sysmon 1 |
| **PowerView** | PowerShell AD enumeration through LDAP / directory APIs | `Get-DomainUser`, `Get-DomainComputer`, `DirectorySearcher`; 4104 |
| **ADRecon** | Enumerates AD objects and configuration | `ADRecon` script names, LDAP and directory queries; 4104 |
| **WinPEAS** | Checks Windows for possible local privilege-escalation weaknesses | PE executable or related process commands; Sysmon 1 |

## Credentials and Kerberos

| Tool | Purpose | Common indicators |
|---|---|---|
| **Mimikatz** | Accesses Windows authentication material, performs DCSync, ticket operations | `sekurlsa::logonpasswords`, `sekurlsa::pth`, `lsadump::dcsync`, `kerberos::ptt`, `kerberos::golden` |
| **SafetyKatz** | Loader that uses Mimikatz functionality | `SafetyKatz`, modified executable metadata, Mimikatz command-line syntax |
| **Rubeus** | Requests, manipulates and imports Kerberos tickets; supports S4U | `asktgt`, `s4u`, `/aes256:`, `/createnetonly:`, `/msdsspn:`, `/impersonateuser:`, `/ptt` |
| **Impacket** | Python tooling for Windows network protocols, authentication and remote execution | Tools such as `secretsdump.py`, `wmiexec.py`, `psexec.py`; combine network and host evidence |

## Remote execution

| Mechanism | Typical host artefacts | What to corroborate |
|---|---|---|
| **WinRM / PowerShell remoting** | `wsmprovhost.exe`; child `powershell.exe`, `cmd.exe`, `whoami.exe`, etc. | 4624 Type 3, Kerberos, session Logon ID, source address, process GUID tree |
| **WMI remote execution** | Often `WmiPrvSE.exe` as process parent | Process arguments, destination authentication and WMI telemetry |
| **PsExec-style service execution** | `services.exe` and service creation/launch; variable service names | System 7045 / other service evidence, Sysmon 1, 4624 Type 3 |
| **RDP** | RemoteInteractive 4624 Type 10; interactive session processes | Source IP, session IDs and later process execution |

## Authentication fields worth remembering

| Event / field | Interpretation |
|---|---|
| Security 4624 `Logon_Type=3` | Successful network logon on the destination machine |
| Security 4624 `Logon_Type=9` | NewCredentials session, not proof of successful remote access |
| Security 4624 `Logon_Type=10` | RemoteInteractive session, commonly RDP |
| Security 4624 `TargetLogonId` | Target session identifier; correlate with same-host Sysmon `LogonId` |
| Security 4768 | TGT request recorded on a DC; `Status=0x0` means success |
| Security 4769 | Service-ticket request recorded on a DC; ticket issuance alone does not prove access |
| `TicketEncryptionType=0x11` | AES128 issued ticket encryption |
| `TicketEncryptionType=0x12` | AES256 issued ticket encryption |
| `TicketEncryptionType=0x17` | RC4-HMAC issued ticket encryption, not automatic evidence of an attack |
| Sysmon 1 `Image` | Executable that actually ran |
| Sysmon 1 `CommandLine` | Command line supplied at launch (not commands typed later inside an interactive tool) |
| Sysmon 11 `Image` | Process responsible for a file creation or overwrite |
| Sysmon 11 `TargetFilename` | File created or overwritten |

### Kerberos SPN primer

A Service Principal Name commonly looks like `service/hostname`. Examples: `HTTP/CLIENT03` (HTTP-class service), `CIFS/CLIENT03` (SMB), `LDAP/ABDULLAH` (LDAP), `HOST/CLIENT03` (host-related services). The SPN is a **Kerberos service identity**, not proof that a remote application was reached successfully.

TGT issuance (4768) → service ticket issuance (4769) → successful destination authentication (4624 Type 3) is a useful evidence progression. Link event times, identities, source addresses, service names and logon-session IDs rather than inferring the later stage from the earlier one.

## Further reading

- [Microsoft — 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) · [4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768) · [4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [Microsoft — Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [GhostPack Rubeus](https://github.com/GhostPack/Rubeus) · [BloodHound collection](https://github.com/SpecterOps/BloodHound-Legacy/wiki/Data-Collector)
