# Web Defender

A Flask middleware that sanitizes all user input (GET, POST, JSON), enforces secure HTTP headers, and logs suspicious activity.  
- Strips/escapes all HTML, JS, and CSS from input.
- Doesn't interfere with app format, gives sanitized input for your app.
- Rotates logs, flags suspicious cookies.
- Hardened CSP and secure session cookies.

**Usage:**  
`python main.py`  
Integrate or reverse-proxy for instant protection.(NOT PRODUCTION READY, OR IT IS. IDRK. ITS COOL ITS NICE)
