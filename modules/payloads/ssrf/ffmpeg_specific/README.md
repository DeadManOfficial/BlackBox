# FFmpeg-Specific SSRF Payloads

Payloads targeting FFmpeg's protocol handlers for SSRF attacks.

## Reference
- TikTok FFmpeg SSRF (HackerOne #1062888 - $2,727)
- FFmpeg Security Advisories

## Protocols

| Protocol | Risk | Use Case |
|----------|------|----------|
| `concat:` | High | Chain multiple URLs |
| `subfile:` | Medium | Read file portions |
| `lavfi:` | Medium | Filter-based reads |
| `hls:` | High | M3U8 playlist loading |
| `data:` | Medium | Inline payload delivery |
| `gopher:` | Critical | Backend service exploitation |

## Usage

```python
from blackbox.modules.payloads.ssrf import SSRFPayloads

payloads = SSRFPayloads()
# Use with video upload endpoints that process with FFmpeg
```

## Detection

Look for endpoints that:
1. Accept video/audio uploads
2. Generate thumbnails
3. Transcode media
4. Extract metadata from media files

## Mitigation

1. Disable dangerous FFmpeg protocols: `-protocol_whitelist file,http,https`
2. Run FFmpeg in isolated network namespace
3. Block metadata service IPs at firewall level
4. Use allowlist for input URLs
