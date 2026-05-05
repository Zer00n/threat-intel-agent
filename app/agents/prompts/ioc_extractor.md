Extract IOCs (Indicators of Compromise) from the provided text.

Types to extract:
- IPv4/IPv6 addresses
- Domains and URLs
- File hashes (MD5, SHA1, SHA256)
- Email addresses
- File paths (Windows and Linux)

Do NOT include:
- Example/test domains (example.com, localhost)
- RFC1918 private addresses (10.x, 172.16-31.x, 192.168.x)
- Version numbers that look like IPs
- Schema URLs (schema.org, w3.org)

Look for semantic mentions like:
- "C2 server: x.x.x.x"
- "delivery domain: evil.com"
- "dropper hash: abc123..."
