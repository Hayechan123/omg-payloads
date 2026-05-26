from flask import Flask, render_template, request, jsonify
import requests
import ssl
import socket
import urllib.parse
import concurrent.futures
from datetime import datetime

app = Flask(__name__)

SENSITIVE_PATHS = [
    "/.git/config", "/.env", "/admin", "/admin/login", "/robots.txt",
    "/sitemap.xml", "/.htaccess", "/wp-admin", "/wp-login.php",
    "/phpinfo.php", "/info.php", "/test.php", "/config.php",
    "/backup.zip", "/backup.sql", "/db.sql", "/database.sql",
    "/api/v1/users", "/api/users", "/swagger.json", "/openapi.json",
    "/.DS_Store", "/Thumbs.db", "/web.config", "/server-status",
    "/server-info", "/.well-known/security.txt",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS - HTTPS 강제 설정",
    "Content-Security-Policy": "CSP - XSS 방지",
    "X-Frame-Options": "클릭재킹 방지",
    "X-Content-Type-Options": "MIME 타입 스니핑 방지",
    "Referrer-Policy": "리퍼러 정보 노출 제어",
    "Permissions-Policy": "브라우저 기능 제한",
    "X-XSS-Protection": "XSS 필터 (구형)",
    "Cross-Origin-Opener-Policy": "COOP - 크로스오리진 격리",
    "Cross-Origin-Embedder-Policy": "COEP - 크로스오리진 임베드 제한",
    "Cross-Origin-Resource-Policy": "CORP - 리소스 공유 제한",
}

LEAKY_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Generator", "X-Runtime",
]


def check_headers(url, session):
    result = {"name": "보안 헤더 분석", "findings": []}
    try:
        resp = session.get(url, timeout=10, allow_redirects=True)
        headers = resp.headers

        missing = []
        present = []
        for h, desc in SECURITY_HEADERS.items():
            if h.lower() in {k.lower() for k in headers}:
                val = headers.get(h, "")
                present.append({"header": h, "value": val, "desc": desc})
            else:
                missing.append({"header": h, "desc": desc})

        leaky = []
        for h in LEAKY_HEADERS:
            if h.lower() in {k.lower() for k in headers}:
                leaky.append({"header": h, "value": headers.get(h, "")})

        result["findings"] = {
            "missing": missing,
            "present": present,
            "leaky": leaky,
            "status_code": resp.status_code,
        }
    except Exception as e:
        result["error"] = str(e)
    return result


def check_sensitive_paths(url, session):
    result = {"name": "민감 파일/경로 노출", "findings": []}
    base = url.rstrip("/")
    found = []
    not_found = []

    def probe(path):
        try:
            r = session.get(base + path, timeout=6, allow_redirects=False)
            return path, r.status_code
        except Exception:
            return path, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(probe, p): p for p in SENSITIVE_PATHS}
        for future in concurrent.futures.as_completed(futures):
            path, code = future.result()
            if code in (200, 301, 302, 403):
                risk = "높음" if code == 200 else "중간"
                found.append({"path": path, "status": code, "risk": risk})
            else:
                not_found.append(path)

    result["findings"] = {"found": sorted(found, key=lambda x: x["path"]), "total_checked": len(SENSITIVE_PATHS)}
    return result


def check_ssl(url):
    result = {"name": "SSL/HTTPS 분석", "findings": {}}
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        result["findings"]["https"] = False
        result["findings"]["note"] = "HTTPS를 사용하지 않음"
        return result

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.utcnow()).days

                result["findings"] = {
                    "https": True,
                    "tls_version": version,
                    "cipher": cipher[0] if cipher else "알 수 없음",
                    "cert_expiry": cert["notAfter"],
                    "days_until_expiry": days_left,
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "san": [v for _, v in cert.get("subjectAltName", [])],
                    "expired": days_left < 0,
                    "expiring_soon": 0 <= days_left <= 30,
                }
    except ssl.SSLCertVerificationError as e:
        result["findings"] = {"https": True, "error": f"인증서 검증 실패: {e}"}
    except Exception as e:
        result["findings"] = {"error": str(e)}
    return result


def check_http_redirect(url, session):
    result = {"name": "HTTP → HTTPS 리다이렉트", "findings": {}}
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https":
        http_url = url.replace("https://", "http://", 1)
    else:
        http_url = url

    try:
        r = session.get(http_url, timeout=10, allow_redirects=False)
        if r.status_code in (301, 302, 307, 308):
            location = r.headers.get("Location", "")
            redirects_to_https = location.startswith("https://")
            result["findings"] = {
                "redirects": True,
                "to_https": redirects_to_https,
                "location": location,
                "status": r.status_code,
            }
        else:
            result["findings"] = {"redirects": False, "status": r.status_code}
    except Exception as e:
        result["findings"] = {"error": str(e)}
    return result


def check_cookie_security(url, session):
    result = {"name": "쿠키 보안 설정", "findings": []}
    try:
        r = session.get(url, timeout=10)
        cookies = []
        for cookie in r.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure 플래그 없음")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly 플래그 없음")
            samesite = cookie.get_nonstandard_attr("SameSite")
            if not samesite:
                issues.append("SameSite 미설정")
            cookies.append({
                "name": cookie.name,
                "issues": issues,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "samesite": samesite or "없음",
            })
        result["findings"] = cookies
    except Exception as e:
        result["error"] = str(e)
    return result


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url", "").strip()
    checks = data.get("checks", [])

    if not url:
        return jsonify({"error": "URL을 입력하세요"}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    session = requests.Session()
    session.headers["User-Agent"] = "SecurityScanner/1.0 (Educational)"

    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = {}
        if "headers" in checks:
            futures["headers"] = ex.submit(check_headers, url, session)
        if "paths" in checks:
            futures["paths"] = ex.submit(check_sensitive_paths, url, session)
        if "ssl" in checks:
            futures["ssl"] = ex.submit(check_ssl, url)
        if "redirect" in checks:
            futures["redirect"] = ex.submit(check_http_redirect, url, session)
        if "cookies" in checks:
            futures["cookies"] = ex.submit(check_cookie_security, url, session)

        for key, future in futures.items():
            try:
                results.append(future.result())
            except Exception as e:
                results.append({"name": key, "error": str(e)})

    return jsonify({"url": url, "results": results, "scanned_at": datetime.utcnow().isoformat()})


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
