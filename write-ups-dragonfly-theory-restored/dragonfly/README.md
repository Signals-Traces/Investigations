# Dragonfly — Investigating a phishing email from `.msg` to `.lnk`

**Lab:** [CyberDefenders — T1598.002 Dragonfly](https://cyberdefenders.org/blueteam-ctf-challenges/t1598002-dragonfly/)  
**Environment:** Windows lab VM  
**Tools:** Microsoft Outlook, Didier Stevens' `oledump.py`, Windows File Explorer, PowerShell

## Overview

The Dragonfly exercise begins with an Outlook message (`T1598.msg`) containing an HTML attachment presented as a requested document. The attachment leads to a password-protected ZIP archive containing a Windows shortcut (`.lnk`). The investigation follows that chain, from the email and its transport headers to the shortcut's Target field.

The analysis uses two complementary methods: **Outlook for message-level inspection** and **`oledump.py` for the underlying MSG streams and MAPI properties**. The extracted ZIP is hashed with PowerShell, and the shortcut is examined through its Properties dialog without launching it.

The suspicious HTML was opened only inside the isolated lab environment, as required by the exercise. The `.lnk` file was **not executed**.

## 1. Examine the email in Outlook

Opening `T1598.msg` in Outlook provides the initial context:

- Sender address: `through-work@grow-jp.com`
- Subject: a reply-style subject beginning `Re: Re:`
- Attachment: `Compensation_897179.html`
- Message text: a claim that the attached file is the requested document, plus the password `abc123`

The attachment is HTML rather than a conventional office document. That is worth examining because an HTML file can include links and scripts, even when the email describes it as a document.

Outlook is also useful for reviewing the Internet headers and saving the attachment. Those operations do not require extracting individual MSG streams.

### Relevant theory — `.msg`, MIME, and OLE storage

An **Outlook `.msg` file** is a saved Outlook item. It can store the email body, recipients, sender details, attachments, and other metadata. This particular MSG file uses **OLE Compound File** storage, which organises data in *storages* and *streams*. A storage acts like a directory inside the compound file; a stream holds a sequence of bytes.

A typical **`.eml` file**, by contrast, usually contains an Internet email in RFC 5322/MIME format. Its headers and MIME boundaries are often directly readable as text.

These are different ways of representing email, not different categories of threat. An `.eml` file generally exposes the transport message and its MIME parts; a `.msg` file stores an Outlook item as a collection of typed properties. Both can contain HTML bodies, attachments, and transport headers.

A useful way to separate the concepts is:

| Layer | Question it answers | Example from this case |
| --- | --- | --- |
| Message content | What does the email say or attach? | A reply-style message with an HTML attachment |
| Transport information | How did the message reach the recipient? | `Received` and `Authentication-Results` headers |
| Storage format | How is the saved artifact organised? | An OLE-based `.msg` file |
| Typed metadata | What does a particular field represent? | MAPI property `0x3707001F`, the attachment's long filename |

This distinction matters when selecting tools. Outlook reads the message at the application level. `oledump.py` exposes the storage structure and the property streams beneath that view.

**MIME** (*Multipurpose Internet Mail Extensions*) enables messages to carry different body formats and attachments. A MIME type such as `text/html` describes the declared format of a file or message part. It does not establish whether the content is safe.

## 2. Examine MSG streams using `oledump.py`

The lab includes Didier Stevens' `oledump.py` and several plugins. `plugin_msg` interprets Outlook-specific stream names and property tags.

![The oledump tool directory includes plugin_msg and other plugins.](assets/01-oledump-plugins.png)

From the `Challenge` directory:

```cmd
python ..\Tools\oledump_V0_0_75\oledump.py -p plugin_msg T1598.msg
```

`-p plugin_msg` loads the MSG plugin. The tool enumerates streams and adds labels to recognised MAPI properties. An attachment-related entry appears as:

```text
7: 48 '__attach_version1.0_#00000000/__substg1.0_3707001F'
   Plugin: MSG plugin
   3707 001F: UNI Attach long filename    Compensation_897179.html
```

![Attachment-related MAPI properties in oledump output.](assets/02-msg-streams.png)

The stream number (`7`) is an index in this particular tool output. The more useful identifier is `3707001F`, which describes what the property stores.

### Relevant theory — MAPI properties and property tags

**MAPI** stands for *Messaging Application Programming Interface*. MAPI properties represent fields associated with an Outlook item: subject, sender, message class, message body, attachment filename, attachment bytes, and many others.

A MAPI property tag is made of two hexadecimal values:

| Component | Value | Meaning |
| --- | --- | --- |
| Property ID | `3707` | Attachment long filename (`PR_ATTACH_LONG_FILENAME`) |
| Property type | `001F` | Unicode string |
| Full tag | `0x3707001F` | Property ID and type together |

The prefix `0x` identifies hexadecimal notation; it is not an additional byte in the tag. Another common type, `0102`, identifies binary data.

**How a stream name is constructed.** Consider the actual attachment-property path:

```text
__attach_version1.0_#00000000/__substg1.0_3707001F
```

- `__attach_version1.0_#00000000` identifies a storage for an attachment within the MSG container. Another attachment would normally have a separate storage.
- `__substg1.0_` introduces a stream that stores a property value.
- `3707` identifies the long attachment filename property.
- `001F` specifies its value type: a Unicode string.

A property **ID** and a property **tag** are not interchangeable. The ID selects the field; the type states how the value is represented. For example, the same filename property can use `0x3707001E` for an ANSI string or `0x3707001F` for a Unicode string. The eight-digit tag must therefore be taken from the actual stream under examination.

Some common MAPI property types help when reading output:

| Type suffix | Data type | Example use |
| --- | --- | --- |
| `001F` | Unicode string | Subject, filename, message body |
| `001E` | 8-bit string (often called ANSI) | Older or alternative text properties |
| `0102` | Binary | Attachment contents |
| `0003` | 32-bit integer | Integer-valued message metadata |
| `0040` | Time (`FILETIME`) | Stored timestamps |

A readable filename property tells us **what an attachment is called**; the `37010102` binary property contains **the attachment's bytes**. Neither should be confused with the displayed size or the sequential stream number.

The useful streams in `T1598.msg` include:

| Stream | MAPI tag | Content |
| --- | --- | --- |
| 4 | `37010102` | Binary attachment data |
| 7 | `3707001F` | Long attachment filename: `Compensation_897179.html` |
| 8 | `370E001F` | Attachment MIME type: `text/html` |
| 28 | `007D001F` | Transport message headers |
| 38 | `1000001F` | Plain-text message body |

Stream indices may differ in another MSG file. The MAPI identifiers describe the properties independently of their position in the listing.

### Relevant theory — Choosing between MSG plugins and stream extraction

`oledump.py` enumerates OLE streams; the plugin determines how much meaning is attached to that raw listing:

- **`plugin_msg`** labels individual Outlook streams with MAPI property names and types. It is suitable for finding the headers, attachment name, body, and message class within the container.
- **`plugin_msg_summary`** aims to provide a message-level overview. It is useful for triage but does not replace looking at individual streams when a specific property tag or byte sequence matters.
- **`-s`** selects an enumerated stream by its current index; it is not a MAPI property number.
- **`-d`** dumps the selected stream's raw bytes. Output redirection with `>` stores those bytes in a new file when used in a binary-safe shell.

For example, `-s 28` was chosen because this particular listing identified **stream 28** as `007D001F` (transport headers). In another MSG file, the same property might have a different stream index. Always locate the property before selecting a stream.

The most efficient method is not necessarily the most granular one: a plugin is useful for locating a specific MAPI property, while Outlook may be easier for reading a message or saving its visible attachment.

For example, stream 4 can be extracted directly:

```cmd
python ..\Tools\oledump_V0_0_75\oledump.py -s 4 -d T1598.msg > attachment.html
```

Here `-s 4` selects the stream, `-d` writes its raw bytes, and `>` redirects them to a file. For raw binary redirection in this older Windows environment, **Command Prompt** is preferable to Windows PowerShell 5.1, whose output redirection can change byte encodings. In this investigation the attachment was saved using Outlook instead.

### Relevant theory — Outlook message classes

Every Outlook item has a **message class** describing what kind of item it is. The class in this file is `IPM.Note`, the standard class for an email message. It is an item-type identifier, not a determination of legitimacy.

Other common examples are:

| Message class | Item type |
| --- | --- |
| `IPM.Note` | Email message |
| `IPM.Appointment` | Calendar appointment |
| `IPM.Schedule.Meeting.Request` | Meeting request |
| `IPM.Contact` | Contact |
| `IPM.Task` | Task |
| `IPM.StickyNote` | Outlook note |

Applications may also use specialised or custom message classes. During analysis, the class helps identify the sort of Outlook object being processed and can inform how it should be parsed.

**Why the class exists.** Outlook uses the message class to decide which kind of form, fields, and behaviours an item should have. A meeting request is handled differently from an email; a contact uses a different set of expected fields. The message class sits alongside other MAPI properties—it is not a filename extension or an SMTP header.

A class can also be extended with a more specific suffix, including classes associated with signed or encrypted mail or custom organisational forms. Consequently, `IPM.Note` is useful as an identification clue, but an unfamiliar class is not by itself evidence of malware. The surrounding properties and content still need to be examined.

## 3. Trace the message through its headers

Outlook exposes the complete transport headers under **File → Properties → Internet headers**.

![Outlook Properties showing the Internet headers.](assets/03-outlook-headers.png)

The relevant portion identifies the final public sending server:

```text
Received: from sp12.canonet.ne.jp
 (sp12.canonet.ne.jp [210.134.168.89])
 by [recipient's mail server] (Postfix) ...
 Mon, 27 Jun 2022 16:34:49 +0000 (UTC)
```

An earlier entry records an SMTP submission client:

```text
Received: from localhost
 (wsip-68-109-200-102.mc.at.cox.net [68.109.200.102])
 by smtp12.canonet.ne.jp (Postfix) with ESMTPSA ...
 Tue, 28 Jun 2022 01:34:46 +0900 (JST)
```

The two IP addresses play different roles. `210.134.168.89` was the public mail relay that delivered the message to the recipient's server (and the IP expected by the lab). `68.109.200.102` appears as an earlier submission client. Private `172.21.x.x` addresses in other headers belong to intermediate infrastructure. An IP address in a mail route should not automatically be identified as the attacker's device.

### Relevant theory — How `Received` headers work

A mail server normally prepends a `Received` header when it accepts a message. As a result, the newest entry appears near the top and the earlier hops appear farther down. Reading **from bottom to top** helps reconstruct the route.

Important fields include:

- **`From`** — the sender identity presented to the recipient; it can be falsified.
- **`Return-Path`** — the SMTP envelope sender recorded for bounce handling; it need not match `From`.
- **`Received`** — transfer records added by mail servers, including servers, timestamps, and sometimes IP addresses.
- **`Authentication-Results`** — the receiving system's reported email-authentication checks.

Headers supplied before the message enters trusted infrastructure can be forged. Assessing the route requires attention to which servers are trusted and which are merely named in untrusted header text.

**A few commonly encountered headers:**

| Header | What it represents | Analytical caution |
| --- | --- | --- |
| `From` | Author identity shown to the recipient | Can be spoofed; may differ from the envelope sender |
| `Reply-To` | Address suggested for replies | May point somewhere unrelated to `From` |
| `Return-Path` | Envelope return address recorded at delivery | Relevant to SPF and bounce processing; not necessarily the human author |
| `Received` | A server's account of a transfer into its system | Trust the entries added by known infrastructure before relying on upstream claims |
| `Message-ID` | Identifier usually supplied by the sending system | Useful for correlation, but not proof of authenticity or uniqueness across all systems |
| `Authentication-Results` | Authentication assessments asserted by a mail system | Interpret in the context of the server that created it |

The earliest *visible* `Received` entry is a starting point, not an absolute source of truth. Some providers conceal clients, some insert additional infrastructure, and lines attributed to an untrusted hop can be fabricated.

In the Dragonfly headers, `with ESMTPSA` appears on the earlier client-to-server hop. This is an SMTP submission using an authenticated, TLS-protected connection. That gives useful context for the role of `68.109.200.102`; it does not establish who controlled that client. The later public relay `210.134.168.89` is the server the recipient's infrastructure actually received the message from.

### Calculate the recorded delivery interval

The earliest visible SMTP submission occurred at **28 June 2022, 01:34:46 JST** (`UTC+09:00`). Converted to UTC, that is **27 June 2022, 16:34:46**.

The recipient's server accepted the message at **27 June 2022, 16:34:49 UTC**. The interval between those recorded events is **3 seconds**.

This measures the visible SMTP transit interval, not the time from composing the email to the recipient opening it.

### Relevant theory — SPF, DKIM, DMARC, and mail filtering

The message's `Authentication-Results` header reports:

```text
spf=pass; dkim=none; dmarc=none
```

These checks serve different purposes:

| Mechanism | What it checks | Interpretation in this case |
| --- | --- | --- |
| **SPF** | Whether the connecting server is authorised for the SMTP envelope-sender domain | `pass` — the recipient accepted the sending server as authorised |
| **DKIM** | Whether a domain's cryptographic signature validates the message | `none` — no applicable DKIM signature was reported |
| **DMARC** | Whether SPF/DKIM authentication aligns with the visible From domain, under the domain's policy | `none` — no positive DMARC authentication verdict was reported |

SPF passing does not demonstrate that a message is benign; an attacker can send harmful content through a server authorised for a domain.

**The checks are related, but not interchangeable.** SPF evaluates the permitted sending IP for an envelope domain. DKIM uses a digital signature to protect the message elements covered by that signature and associates them with a signing domain. DMARC considers the relationship between those authenticated domains and the visible `From` domain, subject to domain policy.

Therefore, `spf=pass`, `dkim=none`, and `dmarc=none` should be recorded **as separate results**, rather than condensed into “authentication passed” or “authentication failed”. In particular, `dkim=none` is not the same finding as an invalid signature, and a clean spam-filtering verdict is not evidence that a later archive or shortcut is harmless.

The `X-` fields in these headers are additional metadata supplied by software along the route. Names such as `X-Virus-Scanner` and `X-ESET-Antispam` can help identify which products processed a message, but their presence should be corroborated with trusted infrastructure if the assessment is consequential.

The headers also contain:

```text
X-Virus-Scanner: This message was checked by ESET Mail Security
X-ESET-Antispam: OK
```

These fields identify ESET mail-security components used along the delivery path. Spam filtering and malware detection overlap but are not the same task. The presence of a scanner result indicates that a check took place, not that the attachment is harmless.

## 4. Save the HTML attachment and examine the ZIP

The attachment was saved using **Outlook → File → Save Attachments**, without having to extract stream 4 manually.

![The Save Attachments option in Outlook.](assets/04-save-attachments.png)

Inside the isolated lab VM, opening `Compensation_897179.html` caused a ZIP archive to download. The archive was password-protected, and the email body supplied the password: `abc123`. After extraction, the archive contained a Windows shortcut.

### Relevant theory — HTML attachments and encrypted archives

HTML can display text and formatting, but it can also contain JavaScript and refer to remote content. As an email attachment, it may serve as an intermediate stage that retrieves another file instead of delivering the purported document directly.

Password protection can make automatic inspection harder for security products that cannot decrypt an archive. Neither HTML attachments nor encrypted ZIP files are inherently malicious; their significance comes from content and behaviour. In this exercise, the HTML-to-ZIP transition was observed in the lab.

**Why the stages matter.** The original `.msg`, saved `.html`, downloaded `.zip`, and extracted `.lnk` are different artifacts with different investigative questions:

| Artifact | What to inspect | Typical evidence |
| --- | --- | --- |
| Outlook `.msg` | Metadata, headers, sender, attachments | Routing and original message context |
| HTML attachment | Source and browser behaviour in a controlled environment | Links, scripts, redirects, download logic |
| ZIP archive | File listing, password, contents, hash | Payload packaging and identifiers |
| `.lnk` shortcut | Target, arguments, working directory, metadata | Potential execution instructions |

A browser-driven download does not necessarily mean the HTML contains a hard-coded HTTP link. The behaviour might be produced by script, a redirect, or data embedded in the file. To establish the exact mechanism, analyse the HTML source; the lab observation alone does not resolve that question.

For suspicious attachments, **static inspection comes before execution** unless a controlled detonation step is genuinely required. Opening an HTML file or launching a shortcut can change the environment. In this exercise, the HTML was opened only inside the provided isolated VM to observe the intended ZIP download.

### Calculate the ZIP's MD5 hash

PowerShell includes `Get-FileHash`:

```powershell
Get-FileHash .\downloaded.zip -Algorithm MD5
```

Replace `downloaded.zip` with the actual archive filename. The resulting digest for this lab's ZIP was:

```text
7e42f69b2adce7166408f635a093266e
```

**What a file hash establishes:** A cryptographic hash produces a fixed-length digest from file content. Analysts can compare it against known artifacts or other copies. Hashing the email, HTML attachment, ZIP, and shortcut would produce different digests because they are different byte sequences.

MD5 is still encountered in malware indicators and older exercises, but it has known collision weaknesses. SHA-256 is preferable for security-sensitive integrity comparisons:

```powershell
Get-FileHash .\downloaded.zip -Algorithm SHA256
```

A hash alone neither proves nor disproves that a file is malicious.

### Relevant theory — Hashes as forensic identifiers

A hash function maps a file's bytes to a digest of fixed length. MD5 produces a **128-bit digest**, conventionally written as **32 hexadecimal characters**; SHA-256 produces **256 bits**, written as **64 hexadecimal characters**. A hash is calculated from the entire byte sequence, not from the filename.

This makes hashes valuable for matching samples, deduplicating files, and comparing an acquired artifact with a later copy. The algorithm must always be recorded alongside the value, because an MD5 and a SHA-256 value are not directly comparable.

MD5 is unsuitable where deliberate collisions would undermine integrity guarantees. That does not make an MD5 lookup useless: for a lab question or a legacy malware indicator, it can still act as a practical identifier when combined with contextual evidence. For stronger integrity records and sharing with other analysts, record SHA-256 as well.

When documenting a hash, keep the **exact file hashed**, its path or source, the algorithm, and the digest together. The ZIP hash cannot stand in for a hash of the HTML or extracted shortcut.

## 5. Inspect the shortcut's Target field

The extracted ZIP contained a Windows shortcut (`.lnk`). Rather than opening it, the shortcut was inspected through **right-click → Properties → Shortcut → Target**.

![Windows shortcut Properties, with part of the Target field visible.](assets/05-lnk-target.png)

The Target references `regsvr32` and a `.jpg`-named file under the temporary directory. The investigation also identified the URL associated with the shortcut:

```text
http://23.29.125.210/herALook.dat
```

The URL is an investigation artifact, not a destination to visit. The available Target screenshot shows only part of the command, so the precise full command-line sequence is not reproduced here. The shortcut was inspected statically and not executed.

### Relevant theory — `.lnk` files and living-off-the-land binaries

A Windows **`.lnk` file** stores shortcut metadata: the target application or file, optional command-line arguments, working directory, icon information, and other properties. A shortcut therefore may be more than a convenient pointer to a document—it can cause Windows to run a command.

`regsvr32.exe` is a legitimate Windows utility used to register and unregister COM components. It is also a **living-off-the-land binary** (LOLBin): a built-in operating-system tool that can be abused as part of a malicious command chain.

The `.jpg` extension in the Target does not guarantee that the referenced content is a JPEG image. The extension is a filename convention, not a file-content verification method.

Inspecting the Target field is a useful first step. A deeper examination could parse the `.lnk` structure and its complete command-line arguments, then correlate those details with process creation and network telemetry if available. No execution or compromise is established by this static artifact alone.

**What to inspect in a suspicious shortcut:**

| Field or feature | Why it is useful |
| --- | --- |
| Target executable | Reveals the program Windows would attempt to launch |
| Command-line arguments | May contain a remote address, a script fragment, or an encoded command |
| Working directory | Can affect how relative file paths are resolved |
| Icon and displayed name | May disguise a shortcut as a document |
| Actual extension and file signature | Help distinguish a shortcut or executable from a file merely labelled as an image |

`regsvr32.exe` is signed and supplied with Windows, which explains why its presence is not inherently malicious. It can also be misused as a component in an attack chain. What matters is the **complete command line and its context**, not the executable name in isolation.

The GUI Target field is convenient, but long values may be difficult to read or fully capture. Copying the displayed value to a text editor is useful for initial triage; a static `.lnk` parser is more dependable for collecting all stored arguments. Neither method requires executing the shortcut.

The ATT&CK label attached to this exercise is **T1598.002**, a *Phishing for Information* technique. The observed email/attachment delivery also resembles **T1566.001 (Spearphishing Attachment)**. In an incident report, technique classification should reflect the verified objective and actions, rather than copying the lab title mechanically.

## 6. Reconstructed delivery chain

The artifacts observed in the lab form the following sequence:

```text
Outlook message (T1598.msg)
    └── HTML attachment (Compensation_897179.html)
          └── Password-protected ZIP download
                └── Windows shortcut (.lnk)
                      └── Target references a Windows utility and remote URL
```

The key investigative distinction is between **delivery evidence** and **execution evidence**. The email, attachment, ZIP, and shortcut establish a delivery chain. Establishing that a recipient launched the shortcut, that a command ran, or that a host was compromised would require separate endpoint or network artifacts.

The tool selection follows the evidence rather than forcing a single tool across the entire chain:

| Investigative need | Most direct method in this lab |
| --- | --- |
| Read message text and retrieve the provided password | Open the MSG in Outlook |
| Identify a MAPI property or locate a specific OLE stream | `oledump.py` with `plugin_msg` |
| Trace sender infrastructure and delivery time | Outlook → File → Properties → Internet headers |
| Save the HTML attachment | Outlook → Save Attachments |
| Hash the downloaded ZIP | PowerShell `Get-FileHash` |
| Inspect the shortcut without launching it | `.lnk` → Properties → Shortcut → Target |

The available artifacts demonstrate a delivery chain, not an observed endpoint compromise. Process, network, or endpoint telemetry would be needed to demonstrate that the shortcut was launched or a subsequent stage executed.

## References

- [CyberDefenders — Dragonfly (T1598.002)](https://cyberdefenders.org/blueteam-ctf-challenges/t1598002-dragonfly/)
- [Didier Stevens Suite — `oledump.py` and MSG plugins](https://github.com/DidierStevens/DidierStevensSuite)
- [Microsoft — PidTagAttachLongFilename](https://learn.microsoft.com/en-us/office/client-developer/outlook/mapi/pidtagattachlongfilename-canonical-property)
- [Microsoft — Message classes and MAPI properties](https://learn.microsoft.com/en-us/office/client-developer/outlook/mapi/message-classes)
