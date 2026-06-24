# Enterprise Grade Web Application VAPT Scanner 🛡️

An advanced, automated Vulnerability Assessment and Penetration Testing (VAPT) utility built with Python. This lightweight auditing engine simulates modern attack vectors against authorized target applications, mapping vulnerabilities against the **OWASP Top 10** framework and compiling executive-grade HTML risk reports.

---

## 🔬 Core Security Test Modules
The pipeline executes **10 distinct structural security audits** simultaneously:
1. **SQL Injection (SQLi):** Simulates error-based and boolean-based database manipulation via input parameters.
2. **Cross-Site Scripting (XSS):** Detects execution gaps in contextual input reflections and HTML entry forms.
3. **Remote Code Execution (RCE):** Evaluates application boundary security against system command injections.
4. **Local File Inclusion (LFI):** Tests directory traversal parameters for high-risk system file disclosures.
5. **Cross-Site Request Forgery (CSRF):** Inspects state-changing `POST` vectors for valid Anti-CSRF cryptographic tokens.
6. **Cross-Origin Resource Sharing (CORS):** Identifies insecure or wildcard domain configurations allowing cross-domain data theft.
7. **Open Redirect Validation:** Assesses dynamic navigation routing components against phishing redirect vulnerabilities.
8. **Sensitive Directory Bruteforcing:** Scans endpoints for exposed dotfiles (`.env`, `.git`) and administrative configurations.
9. **Security Headers Verification:** Validates the implementation of server defenses (`CSP`, `HSTS`, `X-Frame-Options`).
10. **Session Token Hardening Audit:** Inspects browser cookies for `Secure` and `HttpOnly` security flag compliances.

---

## 🚀 Installation & Usage

### 1. Setup the Environment
Ensure you have Python 3.x installed on your workstation, then clone the repository:
```bash
git clone [https://github.com/emranhossainx1/enterprise-vapt-scanner.git](https://github.com/emranhossainx1/enterprise-vapt-scanner.git)
cd enterprise-vapt-scanner

##Install Required Dependencies
pip install -r requirements.txt

##Run the Scanner
python enterprise_vapt_scanner.py
