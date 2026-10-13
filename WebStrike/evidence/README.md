# Recovered Wireshark stream text

The plain-text files here were transcribed from **user-provided Follow Stream output**. They are evidence derivatives, not a replacement for the source PCAP. The capture was not made available for direct reprocessing.

| Stream | Contents |
|---|---|
| [`04`](tcp-stream-04-rejected-upload.txt) | First PHP upload (`image.php`), application rejection |
| [`05`](tcp-stream-05-accepted-upload.txt) | Renamed PHP upload (`image.jpg.php`), application reports success |
| [`12`](tcp-stream-12-shell-get.txt) | GET request to uploaded script; no HTTP response shown |
| [`13`](tcp-stream-13-reverse-shell.txt) | Interactive commands and `/etc/passwd` output, with a capture gap |
| [`14`](tcp-stream-14-http-post-and-501.txt) | Literal 11-byte POST body `/etc/passwd`, HTTP 501 response |

Return to [main investigation](../README.md).
