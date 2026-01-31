# PortSwigger Web Security Academy Lab Report: SQL Injection Vulnerability Exploitation

**Report ID:** PS-LAB-001
**Author:** Venu Kumar(Venu)
**Date:** January 30, 2026
**Lab Version:** PortSwigger Web Security Academy – SQL Injection Lab (Apprentice Level).

## Executive Summary
**Vulnerability Type:** SQL injection allowing retrieval of hidden data.
**Severity:** High (CVSS 3.1 Score: 8.6) “AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N”
**Description:** A SQL injection vulnerability was identified in the `category` parameter of the product listing endpoint (`/filter`) on a simulated “e-commerce” website. The flaw allowed bypassing the `WHERE` clause restrictions (specifically the `released = 1` filter) to retrieve hidden/unreleased products. Exploitation was performed manually by injecting payloads to manipulate the SQL query logic.
**Impact:** In a production environment, this could lead to unauthorized exposure of sensitive data (e.g., unreleased products, user data if extended). Attackers could potentially extract database contents, credentials, or escalate to more severe attacks.
**Status:** Successfully exploited in a controlled lab environment only; no real-world systems were affected. This report is for educational purposes.

## Environment and Tools Used
**Target:** Simulated “e-commerce” website from PortSwigger Web Security Academy (lab URL: e.g., `https://*.web-security-academy.net`)
**Browser:** Google Chrome (Version 120.0 or similar).
**Tools:** “Burp Suite” – for request interception, modification, and analysis.
**Operating System:** Windows 11
**Test Date and Time:** January 30, 2026, approximately 04:52 PM IST.

## Methodology
The lab was conducted following ethical hacking best practices in a safe, simulated environment with no risk to production systems.
1. Accessed the lab via the "Access the lab" button in the PortSwigger Web Security Academy.
2. Copied the base URL and added it to Burp Suite as the target scope.
3. Enabled Intercept in Burp Proxy and navigated to the "Gifts" category to capture the HTTP request.
4. Disabled Intercept after capturing, then manually modified the `category` parameter:
- `category='` → triggered a database error (indicating lack of sanitization).
- `category=' OR 1=1 --` → bypassed the filter, returning all products (including hidden/unreleased ones).
5. Analyzed captured requests and responses in Burp Suite's **Target** and **Proxy > HTTP history** tabs for confirmation.
  
## Detailed Findings
**Vulnerable Endpoint:** `GET /filter?category=...`
**Original Request (Captured in Burp Proxy):**
```http
GET /filter?category=gifts HTTP/1.1
Host: *.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Connection: close
...

Modified Request 1 (Injection Test – Error Triggered):
GET/academyLabHeader HTTP/1.1
Host: 0a87007f046070f081585d78004f00a1.web-security-academy.net
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Upgrade: websocket
Origin: https://0a87007f046070f081585d78004f00a1.web-security-academy.net
Sec-WebSocket-Version: 13
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: session=s3gN1RIZ0e4OFCjZkUNXiVXKDZztcH1K
Sec-WebSocket-Key: 5NDu04fLx88gsCDOxRsXfA==

Response:
GET /academyLabHeader HTTP/1.1
Host: 0a87007f046070f081585d78004f00a1.web-security-academy.net
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Upgrade: websocket
Origin: https://0a87007f046070f081585d78004f00a1.web-security-academy.net
Sec-WebSocket-Version: 13
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: session=s3gN1RIZ0e4OFCjZkUNXiVXKDZztcH1K
Sec-WebSocket-Key: 5NDu04fLx88gsCDOxRsXfA==

Modified Request 2 (Successful Exploitation):
GET/academyLabHeader HTTP/1.1
Host: 0acf005f0488107b808908bd008700e5.web-security-academy.net
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Upgrade: websocket
Origin: https://0acf005f0488107b808908bd008700e5.web-security-academy.net
Sec-WebSocket-Version: 13
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: session=iz6CHORT2gXm1jR31DqzpzraS52nG6u6
Sec-WebSocket-Key: kIp3X5lke02+5j4hM+E02g==

Response:
HTTP/1.1 101 Switching Protocol
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: m8N8EOzb5enZPX0VbJ+02PZaR2I=
Content-Length: 0

**Proof of Error (Injection Test)**
![SQL Injection Error Triggered](https://github.com/venu-maxx/PortSwigger-LAb-1/blob/588d79eab4cd2db473538ef5407f857095dae2cc/error-internal-server.jpg)
*Figure 1: Database error after injecting single quote ('), confirming lack of input sanitization.*

**Proof of Successful Exploitation**
![All Products Displayed After Bypass]:
*Figure 2: Full product listing retrieved after payload `' OR 1=1 --`, bypassing the released=1 filter.*

![Lab Solved Congratulations]:
*Figure 3: PortSwigger Academy confirmation of lab completion.*

Exploitation Explanation:
The injected single quote (') closed the string literal in the SQL query. Appending OR 1=1 -- made the WHERE condition always true and commented out the remainder of the query (e.g., AND released = 1). This classic boolean-based SQL injection technique confirmed the vulnerability.

Risk Assessment
● Likelihood of Exploitation: High (user-controlled parameter with no sanitization or parameterization).
● Potential Impact: High to Critical — exposure of restricted data; in real applications, could enable full database enumeration, credential theft, or privilege escalation.
● Affected Components: Backend database (likely MySQL or PostgreSQL based on common PortSwigger lab setups and error patterns).

Recommendations for Remediation
● Use prepared statements or parameterized queries (e.g., PDO in PHP, PreparedStatement in Java) to separate data from SQL code.
● Implement strict input validation and sanitization for all user-supplied parameters.
● Deploy a Web Application Firewall (WAF) to detect and block common SQL injection patterns.
● Perform regular code reviews, static analysis, and dynamic scanning (e.g., using OWASP ZAP, sqlmap, or Burp Scanner).
● Apply the principle of least privilege to database accounts used by the application.

Conclusion and Lessons Learned
This lab successfully demonstrated the identification and manual exploitation of a SQL injection vulnerability using Burp Suite.
Key Takeaways:
● Always test query parameters for input validation flaws.
● Understand how SQL query structure can be manipulated with simple payloads like ' OR 1=1 --.
● This exercise strengthened skills in reconnaissance, payload crafting, HTTP interception, and professional report writing for ethical hacking and penetration testing scenarios.

References
● PortSwigger Web Security Academy: SQL Injection.
● Lab specifically: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
