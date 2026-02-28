from __future__ import annotations

import re

from core.models import LogEvent, MitreTechnique

_PATH_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e|%252e)", re.IGNORECASE)
_SQL_INJECTION_RE = re.compile(
    r"(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|select\s+.*\s+from|"
    r"insert\s+into|drop\s+table|sleep\s*\(|benchmark\s*\(|"
    r"0x[0-9a-f]+|char\s*\(|concat\s*\(|load_file\s*\(|"
    r"information_schema|%27|%22)",
    re.IGNORECASE,
)
_XSS_RE = re.compile(
    r"(<script|javascript:|on\w+\s*=|<img\s+.*onerror|<svg\s+.*onload|"
    r"alert\s*\(|document\.cookie|%3cscript|%3csvg)",
    re.IGNORECASE,
)
_COMMAND_INJECTION_RE = re.compile(
    r"(;\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|ruby)\b|"
    r"\|\s*(cat|ls|id|whoami)|`[^`]+`|\$\(.*\))",
    re.IGNORECASE,
)
_SENSITIVE_PATH_RE = re.compile(
    r"(/\.env|/\.git|/\.htaccess|/\.htpasswd|/wp-config|/config\.php|"
    r"/etc/passwd|/etc/shadow|/proc/self|/\.ssh|/\.aws|"
    r"/server-status|/server-info|/phpinfo|/debug|/actuator)",
    re.IGNORECASE,
)
_SCANNER_PATH_RE = re.compile(
    r"(/wp-admin|/wp-login|/wp-content|/xmlrpc\.php|/phpmyadmin|"
    r"/admin|/administrator|/manager|/console|/cgi-bin|"
    r"/\.well-known|/robots\.txt|/sitemap\.xml)",
    re.IGNORECASE,
)
_WEBSHELL_RE = re.compile(
    r"(c99|r57|webshell|cmd\.php|shell\.php|eval\s*\(|"
    r"base64_decode|system\s*\(|passthru\s*\(|exec\s*\()",
    re.IGNORECASE,
)
_SCANNER_UA_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|"
    r"wpscan|acunetix|nessus|openvas|burpsuite|"
    r"python-requests|go-http-client|libwww-perl|"
    r"wget|curl/\d|scrapy|httpclient)",
    re.IGNORECASE,
)
_BOT_UA_RE = re.compile(
    r"(bot|crawler|spider|scan|harvest|extract|scrape)",
    re.IGNORECASE,
)
_SSRF_RE = re.compile(
    r"(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|10\.\d|"
    r"172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1|%00|"
    r"file://|gopher://|dict://|ftp://)",
    re.IGNORECASE,
)
_LOG4SHELL_RE = re.compile(
    r"(\$\{jndi:|%24%7bjndi|%2524%257bjndi)",
    re.IGNORECASE,
)

TECHNIQUE_CATALOG = {
    "T1190": MitreTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
    ),
    "T1595": MitreTechnique(
        technique_id="T1595",
        name="Active Scanning",
        tactic="Reconnaissance",
    ),
    "T1595.001": MitreTechnique(
        technique_id="T1595.001",
        name="Scanning IP Blocks",
        tactic="Reconnaissance",
    ),
    "T1595.002": MitreTechnique(
        technique_id="T1595.002",
        name="Vulnerability Scanning",
        tactic="Reconnaissance",
    ),
    "T1110": MitreTechnique(
        technique_id="T1110",
        name="Brute Force",
        tactic="Credential Access",
    ),
    "T1110.001": MitreTechnique(
        technique_id="T1110.001",
        name="Password Guessing",
        tactic="Credential Access",
    ),
    "T1078": MitreTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Initial Access",
    ),
    "T1071.001": MitreTechnique(
        technique_id="T1071.001",
        name="Web Protocols",
        tactic="Command and Control",
    ),
    "T1059.004": MitreTechnique(
        technique_id="T1059.004",
        name="Unix Shell",
        tactic="Execution",
    ),
    "T1505.003": MitreTechnique(
        technique_id="T1505.003",
        name="Web Shell",
        tactic="Persistence",
    ),
    "T1592": MitreTechnique(
        technique_id="T1592",
        name="Gather Victim Host Information",
        tactic="Reconnaissance",
    ),
    "T1046": MitreTechnique(
        technique_id="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
    ),
    "T1498": MitreTechnique(
        technique_id="T1498",
        name="Network Denial of Service",
        tactic="Impact",
    ),
    "T1499": MitreTechnique(
        technique_id="T1499",
        name="Endpoint Denial of Service",
        tactic="Impact",
    ),
    "T1557": MitreTechnique(
        technique_id="T1557",
        name="Adversary-in-the-Middle",
        tactic="Credential Access",
    ),
    "T1203": MitreTechnique(
        technique_id="T1203",
        name="Exploitation for Client Execution",
        tactic="Execution",
    ),
}


def classify(event: LogEvent) -> list[MitreTechnique]:
    matches: list[MitreTechnique] = []
    path = event.path or ""
    ua = event.user_agent or ""
    method = (event.method or "").upper()
    status = event.status or 0
    full_url = path

    if _PATH_TRAVERSAL_RE.search(full_url):
        matches.append(_with_confidence("T1190", 0.9))

    if _SQL_INJECTION_RE.search(full_url):
        matches.append(_with_confidence("T1190", 0.95))

    if _XSS_RE.search(full_url) or _XSS_RE.search(ua):
        matches.append(_with_confidence("T1203", 0.8))

    if _COMMAND_INJECTION_RE.search(full_url):
        matches.append(_with_confidence("T1059.004", 0.9))

    if _WEBSHELL_RE.search(full_url):
        matches.append(_with_confidence("T1505.003", 0.85))

    if _SSRF_RE.search(full_url):
        matches.append(_with_confidence("T1190", 0.85))

    if _LOG4SHELL_RE.search(full_url) or _LOG4SHELL_RE.search(ua):
        matches.append(_with_confidence("T1190", 0.95))

    if _SENSITIVE_PATH_RE.search(full_url):
        matches.append(_with_confidence("T1592", 0.7))

    if _SCANNER_PATH_RE.search(full_url):
        matches.append(_with_confidence("T1595.002", 0.75))

    if _SCANNER_UA_RE.search(ua):
        matches.append(_with_confidence("T1595.002", 0.8))

    if _BOT_UA_RE.search(ua) and not _SCANNER_UA_RE.search(ua):
        matches.append(_with_confidence("T1595", 0.5))

    if method in {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"} and status >= 400:
        matches.append(_with_confidence("T1190", 0.6))

    if status == 401 or status == 403:
        matches.append(_with_confidence("T1110", 0.4))

    if status >= 500:
        matches.append(_with_confidence("T1499", 0.3))

    seen_ids: set[str] = set()
    deduplicated: list[MitreTechnique] = []
    for technique in matches:
        if technique.technique_id not in seen_ids:
            seen_ids.add(technique.technique_id)
            deduplicated.append(technique)
        else:
            for i, existing in enumerate(deduplicated):
                if existing.technique_id == technique.technique_id:
                    if technique.confidence > existing.confidence:
                        deduplicated[i] = technique
                    break

    deduplicated.sort(key=lambda t: t.confidence, reverse=True)
    return deduplicated


def _with_confidence(technique_id: str, confidence: float) -> MitreTechnique:
    base = TECHNIQUE_CATALOG[technique_id]
    return MitreTechnique(
        technique_id=base.technique_id,
        name=base.name,
        tactic=base.tactic,
        confidence=confidence,
    )
