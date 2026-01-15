from __future__ import annotations

from core.normalization import normalize_message, normalize_path, path_extension, referrer_domain


class TestNormalizePath:
    def test_strips_query_string(self):
        result = normalize_path("/api/v1/items/123?debug=1&verbose=true")
        assert "?" not in result

    def test_masks_numbers(self):
        result = normalize_path("/api/v1/items/123")
        assert "<NUM>" in result
        assert "123" not in result

    def test_masks_hex_tokens(self):
        result = normalize_path("/api/v1/objects/a1b2c3d4e5f6")
        assert "<HEX>" in result

    def test_preserves_structure(self):
        result = normalize_path("/api/v1/items/42")
        assert result.startswith("/api/v")
        assert result.count("/") == 4

    def test_empty_path(self):
        assert normalize_path("") == ""

    def test_root_path(self):
        assert normalize_path("/") == "/"


class TestNormalizeMessage:
    def test_masks_ip_addresses(self):
        result = normalize_message("Connection from 192.168.1.1 port 22")
        assert "<IP>" in result
        assert "192.168.1.1" not in result

    def test_masks_uuids(self):
        result = normalize_message("Request id=550e8400-e29b-41d4-a716-446655440000")
        assert "<UUID>" in result

    def test_masks_hex_values(self):
        result = normalize_message("Token 0xdeadbeef received")
        assert "<HEX>" in result
        assert "0xdeadbeef" not in result

    def test_masks_numbers(self):
        result = normalize_message("Processed 42 items in 100 ms")
        assert "<NUM>" in result
        assert "42" not in result

    def test_combined_replacements(self):
        result = normalize_message("IP 10.0.0.1 sent 0xab01 with 99 bytes")
        assert "<IP>" in result
        assert "<HEX>" in result
        assert "<NUM>" in result


class TestPathExtension:
    def test_js_extension(self):
        assert path_extension("/static/app.js") == ".js"

    def test_extension_through_query(self):
        assert path_extension("/static/app.js?v=2") == ".js"

    def test_no_extension(self):
        assert path_extension("/api/v1/users") == ""

    def test_php_extension(self):
        assert path_extension("/index.php") == ".php"

    def test_uppercase_normalized(self):
        assert path_extension("/file.CSS") == ".css"


class TestReferrerDomain:
    def test_extracts_domain(self):
        assert referrer_domain("https://example.com/page?q=1") == "example.com"

    def test_dash_returns_empty(self):
        assert referrer_domain("-") == ""

    def test_none_returns_empty(self):
        assert referrer_domain(None) == ""

    def test_empty_returns_empty(self):
        assert referrer_domain("") == ""

    def test_domain_with_port(self):
        assert referrer_domain("https://example.com:8080/path") == "example.com:8080"
