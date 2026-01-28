# Reverse Engineering Methodology
## Static & Dynamic Analysis Framework

**Version:** 1.0
**Purpose:** Systematic approach to reverse engineering for security research

---

## Overview

This methodology covers:
- Static analysis (code review without execution)
- Dynamic analysis (runtime instrumentation)
- Protocol analysis (network traffic)
- Cipher identification (cryptographic algorithms)
- Obfuscation handling (deobfuscation techniques)

---

## Phase 1: Static Analysis Workflow

### 1.1 JavaScript Analysis

**Tools:** Browser DevTools, Beautifier, AST parsers

**Workflow:**
```
1. Identify target JS files
   ├── Network tab → Filter JS
   ├── Source maps if available
   └── Webpack/bundle analysis

2. Extract and format
   ├── Download raw bundles
   ├── Beautify/prettify
   └── Source map decode

3. Analyze structure
   ├── Entry points
   ├── Module boundaries
   └── Export/import graph

4. Extract artifacts
   ├── API endpoints
   ├── Secrets/keys
   ├── Crypto functions
   └── Validation logic
```

**Extraction Patterns:**
```javascript
// API Endpoints
/['"`](\/api\/[a-zA-Z0-9\/_-]+)['"`]/g
/fetch\s*\(\s*['"`]([^'"]+)['"`]/g

// Secrets
/api[_-]?key[\s]*[:=][\s]*['"][a-zA-Z0-9]{20,}/gi
/AKIA[0-9A-Z]{16}/g
/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g

// Crypto Functions
/function\s+\w*(sign|hash|encrypt|decrypt|cipher)\w*\s*\(/gi
```

### 1.2 Binary Analysis

**Tools:** Ghidra, IDA Pro, Binary Ninja, radare2

**Workflow:**
```
1. Identify binary type
   ├── file command
   ├── Architecture (x86, ARM, etc.)
   └── Protections (stripped, packed)

2. Initial analysis
   ├── Strings extraction
   ├── Import/export tables
   └── Section headers

3. Disassembly
   ├── Entry point identification
   ├── Function discovery
   └── Cross-references

4. Decompilation
   ├── Pseudo-C generation
   ├── Type recovery
   └── Variable naming
```

### 1.3 Mobile App Analysis

**Android (APK):**
```bash
# Decompile
apktool d target.apk -o decompiled/
jadx -d jadx-output/ target.apk

# Analyze
grep -r "api" jadx-output/
grep -r "secret" jadx-output/
grep -r "http" jadx-output/
```

**iOS (IPA):**
```bash
# Extract
unzip target.ipa -d extracted/

# Analyze binary
otool -L extracted/Payload/*.app/*
class-dump extracted/Payload/*.app/*
```

---

## Phase 2: Dynamic Analysis Workflow

### 2.1 Browser Instrumentation

**Tools:** Chrome DevTools, Playwright, Puppeteer

**Workflow:**
```javascript
// Hook fetch API
const originalFetch = window.fetch;
window.fetch = async (...args) => {
    console.log('[FETCH]', args);
    const response = await originalFetch(...args);
    console.log('[RESPONSE]', response.clone());
    return response;
};

// Hook XMLHttpRequest
const originalOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(...args) {
    console.log('[XHR]', args);
    return originalOpen.apply(this, args);
};

// Hook crypto operations
const originalSubtle = window.crypto.subtle;
// ... wrap methods
```

### 2.2 Frida Instrumentation

**Mobile/Desktop Runtime Hooking:**

```javascript
// frida-hook.js
Java.perform(function() {
    // Hook HTTP client
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    OkHttpClient.newCall.implementation = function(request) {
        console.log('[REQUEST] ' + request.url());
        return this.newCall(request);
    };

    // Hook crypto
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[CIPHER] Input: ' + input);
        var result = this.doFinal(input);
        console.log('[CIPHER] Output: ' + result);
        return result;
    };
});
```

**Usage:**
```bash
frida -U -f com.target.app -l frida-hook.js --no-pause
```

### 2.3 Network Interception

**Tools:** mitmproxy, Burp Suite, Charles

**mitmproxy Script:**
```python
from mitmproxy import http

def request(flow: http.HTTPFlow):
    # Log all requests
    print(f"[REQ] {flow.request.method} {flow.request.url}")

    # Capture specific headers
    if 'X-Bogus' in flow.request.headers:
        print(f"  X-Bogus: {flow.request.headers['X-Bogus']}")

def response(flow: http.HTTPFlow):
    # Analyze responses
    if flow.response.headers.get('content-type', '').startswith('application/json'):
        print(f"[JSON] {flow.response.text[:500]}")
```

---

## Phase 3: Protocol Analysis

### 3.1 Request/Response Capture

**Structure:**
```
REQUEST:
├── Method: POST
├── URL: /api/v1/auth/login
├── Headers:
│   ├── X-Bogus: DFSxxx...
│   ├── User-Agent: ...
│   └── Cookie: ...
├── Body: {"username": "...", "password": "..."}
└── Timestamp: 1706295600000

RESPONSE:
├── Status: 200
├── Headers: ...
└── Body: {"token": "...", "user": {...}}
```

### 3.2 Parameter Analysis

**Identification:**
| Parameter | Type | Purpose | Mutable |
|-----------|------|---------|---------|
| X-Bogus | Header | Anti-fraud signature | No |
| msToken | Cookie | Session token | No |
| _signature | Query | Request signature | No |
| device_id | Query | Device fingerprint | Maybe |

### 3.3 Replay Testing

```python
import requests
import time

def test_replay(original_request):
    """Test if request can be replayed"""

    # Immediate replay
    r1 = requests.request(**original_request)

    # Delayed replay (1 min)
    time.sleep(60)
    r2 = requests.request(**original_request)

    # Modified replay
    original_request['headers']['X-Bogus'] = 'invalid'
    r3 = requests.request(**original_request)

    return {
        'immediate': r1.status_code,
        'delayed': r2.status_code,
        'modified': r3.status_code
    }
```

---

## Phase 4: Cipher Identification

### 4.1 Hash Algorithm Detection

**Magic Constants:**
| Algorithm | Constants |
|-----------|-----------|
| MD5 | 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 |
| SHA-1 | Above + 0xc3d2e1f0 |
| SHA-256 | 0x6a09e667, 0xbb67ae85, 0x3c6ef372... |
| CRC32 | 0xedb88320 |

**Detection Script:**
```python
MD5_CONSTANTS = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
SHA1_CONSTANTS = MD5_CONSTANTS + [0xc3d2e1f0]
SHA256_CONSTANTS = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a]

def identify_hash(code):
    for const in MD5_CONSTANTS:
        if hex(const) in code or str(const) in code:
            return "MD5"
    # ... continue for other algorithms
```

### 4.2 Encryption Detection

**AES S-Box (first 16 bytes):**
```
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
```

**Block Cipher Patterns:**
- 16-byte block operations (AES)
- 8-byte block operations (DES, 3DES)
- CBC mode: XOR with previous block
- CTR mode: Counter increment

### 4.3 Substitution Cipher

**Detection:**
```python
def detect_substitution(ciphertext, plaintext):
    """Detect character substitution patterns"""
    if len(ciphertext) != len(plaintext):
        return None

    mapping = {}
    for c, p in zip(ciphertext, plaintext):
        if c in mapping and mapping[c] != p:
            return None  # Inconsistent mapping
        mapping[c] = p

    return mapping
```

---

## Phase 5: Obfuscation Handling

### 5.1 JavaScript Obfuscation Types

| Type | Detection | Deobfuscation |
|------|-----------|---------------|
| String Array | `_0x1234[0x1]` | Extract array, substitute |
| Hex Encoding | `\x41\x42` | Decode hex |
| Unicode | `\u0041` | Decode unicode |
| Eval-based | `eval(...)` | Hook eval, log |
| Control Flow | Switch + array | Trace execution |
| Dead Code | Unreachable blocks | CFG analysis |

### 5.2 Deobfuscation Script

```javascript
// String array deobfuscation
function deobfuscateStringArray(code) {
    // Find string array
    const arrayMatch = code.match(/var\s+(\w+)\s*=\s*\[([^\]]+)\]/);
    if (!arrayMatch) return code;

    const [_, varName, arrayContent] = arrayMatch;
    const strings = arrayContent.split(',').map(s =>
        s.trim().replace(/^['"]|['"]$/g, '')
    );

    // Replace references
    const refPattern = new RegExp(`${varName}\\[(\\d+|0x[0-9a-f]+)\\]`, 'gi');
    return code.replace(refPattern, (match, index) => {
        const idx = parseInt(index);
        return `"${strings[idx]}"`;
    });
}
```

### 5.3 Anti-Debug Bypass

```javascript
// Disable debugger statements
const originalDebugger = Function.prototype.constructor;
Function.prototype.constructor = function(...args) {
    if (args[0]?.includes('debugger')) {
        return function() {};
    }
    return originalDebugger.apply(this, args);
};

// Disable console detection
Object.defineProperty(console, '_commandLineAPI', {
    get: function() { return undefined; }
});
```

---

## Tool Integration

### Quick Commands

```bash
# JS Analysis
js-beautify bundle.js -o pretty.js
grep -E "api|secret|key|token" pretty.js

# Binary Analysis
strings binary | grep -i "http\|api\|key"
objdump -d binary | head -100

# Mobile Analysis
apktool d app.apk && grep -r "api" decompiled/

# Network Capture
mitmproxy -s capture.py

# Frida Hook
frida -U -f com.app -l hooks.js
```

### Integration with Framework Tools

```bash
# Use DeadMan Toolkit
js_analyze target="https://target.com/bundle.js"

# Secret scanning
secret_scan_files path="/path/to/js"

# Nuclei templates for JS
nuclei -t ~/nuclei-templates/exposures/
```

---

## Checklist

### Static Analysis
- [ ] Identify all target files
- [ ] Beautify/deobfuscate code
- [ ] Extract endpoints and secrets
- [ ] Map function relationships
- [ ] Identify crypto operations

### Dynamic Analysis
- [ ] Set up instrumentation
- [ ] Hook critical functions
- [ ] Capture request/response
- [ ] Trace execution flow
- [ ] Extract runtime values

### Protocol Analysis
- [ ] Document all parameters
- [ ] Identify signatures
- [ ] Test replay attacks
- [ ] Find bypass methods

### Cipher Analysis
- [ ] Identify algorithm
- [ ] Extract constants/keys
- [ ] Understand input/output
- [ ] Replicate implementation

---

*Reverse Engineering Methodology - Security Research*
*Static → Dynamic → Protocol → Cipher → Bypass*
