# Mobile Security Tests

| Test Type | Tools | What It Covers |
| :--- | :--- | :--- |
| **Static Analysis** | `MobSF`, `qark`, `androbugs` | Insecure storage, hardcoded secrets, WebView config |
| **Dynamic Analysis** | `Frida`, `Objection`, `Burp` | Runtime tampering, SSL pinning bypass |
| **Network** | `mitmproxy`, `Burp` | Cleartext traffic, weak TLS |
| **Reverse Engineering** | `jadx`, `Ghidra`, `Hopper` | Code obfuscation, integrity checks |

Run MobSF in CI on every mobile build artifact.