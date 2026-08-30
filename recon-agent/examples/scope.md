# Example authorization record

Before pointing recon-agent at a real host, keep a short record like this
one for the engagement — who authorized it, what's in scope, and when the
window closes. `--i-am-authorized` is a command-line acknowledgement, not a
substitute for this.

```
Target        : app.example-client.com
Authorized by : Jane Doe, CISO, Example Client Inc.
Scope         : app.example-client.com (HTTP/HTTPS only, no subdomains)
Window        : 2026-08-01 - 2026-08-15
Rules of      : Passive recon only (this tool never exploits, brute-forces,
engagement      or sends anything beyond a single benign GET/TLS handshake
                per probe). Stop immediately if instructed by the client.
```
