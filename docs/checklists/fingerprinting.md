# Device Fingerprinting Checklist

Security research checklist for analyzing device fingerprinting implementations.

Learned from: TikTok device fingerprinting analysis (21+ parameters)

---

## Browser Fingerprinting

### WebGL Fingerprinting
| Parameter | Description | Detection Method |
|-----------|-------------|------------------|
| `RENDERER` | GPU renderer string | `gl.getParameter(gl.RENDERER)` |
| `VENDOR` | GPU vendor string | `gl.getParameter(gl.VENDOR)` |
| `VERSION` | WebGL version | `gl.getParameter(gl.VERSION)` |
| `SHADING_LANGUAGE_VERSION` | GLSL version | `gl.getParameter(gl.SHADING_LANGUAGE_VERSION)` |
| `MAX_TEXTURE_SIZE` | Max texture dimension | `gl.getParameter(gl.MAX_TEXTURE_SIZE)` |
| `MAX_VERTEX_ATTRIBS` | Max vertex attributes | `gl.getParameter(gl.MAX_VERTEX_ATTRIBS)` |
| `MAX_VERTEX_UNIFORM_VECTORS` | Max vertex uniforms | `gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS)` |
| `MAX_VARYING_VECTORS` | Max varying vectors | `gl.getParameter(gl.MAX_VARYING_VECTORS)` |
| `MAX_COMBINED_TEXTURE_IMAGE_UNITS` | Combined tex units | `gl.getParameter(...)` |
| `ALIASED_LINE_WIDTH_RANGE` | Line width range | `gl.getParameter(...)` |
| `ALIASED_POINT_SIZE_RANGE` | Point size range | `gl.getParameter(...)` |
| `MAX_VIEWPORT_DIMS` | Max viewport dimensions | `gl.getParameter(...)` |
| `RED_BITS`, `GREEN_BITS`, etc. | Color depth | `gl.getParameter(...)` |
| Extensions | Supported extensions | `gl.getSupportedExtensions()` |

**Test:** Spoof WebGL parameters to evade fingerprinting.

### Canvas Fingerprinting
| Parameter | Description | Detection Method |
|-----------|-------------|------------------|
| 2D Canvas Hash | Rendering hash | Draw text/shapes, get `toDataURL()` |
| Font Rendering | Font smoothing | Draw text, measure differences |
| Anti-aliasing | Edge smoothing | Draw lines, analyze pixels |
| Shadow rendering | Shadow implementation | `context.shadowBlur` |
| Composite operations | Blend modes | `globalCompositeOperation` |

**Test:** Canvas poisoning to generate random fingerprints.

### Navigator Properties
| Property | Description | Privacy Risk |
|----------|-------------|--------------|
| `navigator.userAgent` | Browser/OS string | Medium |
| `navigator.platform` | OS platform | Low |
| `navigator.language` | Primary language | Low |
| `navigator.languages` | Language preferences | Medium |
| `navigator.hardwareConcurrency` | CPU cores | Medium |
| `navigator.deviceMemory` | RAM (GB) | Medium |
| `navigator.maxTouchPoints` | Touch capability | Low |
| `navigator.webdriver` | Automation flag | Critical |
| `navigator.plugins` | Browser plugins | High |
| `navigator.mimeTypes` | MIME types | Medium |
| `navigator.cookieEnabled` | Cookies enabled | Low |
| `navigator.doNotTrack` | DNT setting | Low |
| `navigator.vendor` | Browser vendor | Low |
| `navigator.connection` | Network info | Medium |
| `navigator.getBattery()` | Battery status | High |
| `navigator.getGamepads()` | Connected gamepads | Medium |

**Critical:** `navigator.webdriver = true` is a bot indicator!

### Screen Properties
| Property | Description | Uniqueness |
|----------|-------------|------------|
| `screen.width` | Screen width | Medium |
| `screen.height` | Screen height | Medium |
| `screen.availWidth` | Available width | Medium |
| `screen.availHeight` | Available height | Medium |
| `screen.colorDepth` | Color depth | Low |
| `screen.pixelDepth` | Pixel depth | Low |
| `screen.orientation` | Orientation | Low |
| `window.devicePixelRatio` | Pixel density | Medium |

### Audio Fingerprinting
| Technique | Description |
|-----------|-------------|
| AudioContext | Web Audio API fingerprinting |
| OscillatorNode | Generate audio, hash output |
| DynamicsCompressor | Compressor characteristics |
| AnalyserNode | Frequency analysis |

---

## Behavioral Fingerprinting

### Mouse/Touch Patterns
| Signal | Description | Detection |
|--------|-------------|-----------|
| Movement speed | Cursor velocity | Track dx/dy over time |
| Click patterns | Click timing | `mousedown`/`mouseup` intervals |
| Scroll behavior | Scroll velocity | `wheel` event analysis |
| Touch pressure | Force Touch/3D Touch | `force` property |
| Gesture patterns | Swipe characteristics | Touch event sequences |

### Keyboard Patterns
| Signal | Description | Detection |
|--------|-------------|-----------|
| Typing speed | Characters per second | `keydown` intervals |
| Key hold duration | Press-release timing | `keydown`/`keyup` delta |
| Error rate | Backspace frequency | Backspace key count |
| Typing rhythm | Inter-key timing | Statistical analysis |

### Timing-Based
| Signal | Description | Detection |
|--------|-------------|-----------|
| Time zone | UTC offset | `new Date().getTimezoneOffset()` |
| System time | Clock drift | Compare with server time |
| Session duration | Time on site | Session start/end |
| Interaction timing | Response latency | Event-to-action timing |

---

## Network Fingerprinting

| Signal | Description | Risk |
|--------|-------------|------|
| IP address | Network location | High |
| DNS resolver | DNS provider | Medium |
| TLS fingerprint (JA3) | TLS handshake | High |
| HTTP/2 fingerprint | H2 settings | Medium |
| WebRTC leak | Local IP | Critical |
| MTU | Packet size | Low |

---

## Anti-Fingerprinting Detection

Signs that a user is attempting to evade fingerprinting:

| Signal | Indicates |
|--------|-----------|
| `navigator.webdriver = undefined` | Spoofed (should be `false` or absent) |
| Canvas data URL is random | Canvas poisoning |
| WebGL parameters mismatch | Spoofed GPU |
| User-Agent doesn't match features | Spoofed UA |
| Consistent fingerprint across sessions | Fingerprint blocking extension |
| `window.chrome` undefined in Chrome | Automation framework |
| Headless indicators | Puppeteer/Playwright |

---

## Bot Detection Signals

### Critical Bot Indicators
1. `navigator.webdriver === true`
2. Missing `window.chrome` in Chrome
3. Headless User-Agent
4. No mouse movement before click
5. Perfect/inhuman interaction timing
6. Missing browser plugins
7. `window.outerHeight === window.innerHeight`
8. `window.Notification.permission === 'denied'` without prompt

### Automation Framework Detection
| Framework | Detection Method |
|-----------|------------------|
| Puppeteer | `window.puppeteer` |
| Playwright | `window.playwright` |
| Selenium | `navigator.webdriver`, `$cdc_` variables |
| PhantomJS | `window.callPhantom` |
| Nightmare | `window.__nightmare` |

---

## Testing Recommendations

### For Security Research
1. **Document all fingerprint parameters** collected by target
2. **Test spoofing resistance** - can fingerprint be evaded?
3. **Check for fingerprint-based rate limiting**
4. **Analyze fingerprint storage** - how long is it retained?
5. **Test cross-domain tracking** - is fingerprint shared?

### Privacy Impact Assessment
- [ ] What data is collected?
- [ ] How long is it stored?
- [ ] Is it shared with third parties?
- [ ] Can users opt out?
- [ ] Is collection disclosed in privacy policy?

---

*DeadMan Toolkit v5.3*
*Learned from TikTok analysis - 21+ fingerprint parameters identified*
