"""Input validation tests (invalid-input testing in the test plan)."""
import pytest

from services.validation import (ValidationError, detect_scan_type, mask_email, validate_domain,
                                 validate_email, validate_reputation_target, validate_username)


@pytest.mark.parametrize("raw, expected", [
    ("example.com", "example.com"),
    ("  EXAMPLE.com.  ", "example.com"),
    ("https://www.example.com/login?x=1", "www.example.com"),
    ("*.example.org", "example.org"),
    ("demo-corp.test", "demo-corp.test"),
    ("bücher.de", "xn--bcher-kva.de"),
])
def test_valid_domains(raw, expected):
    assert validate_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", "localhost", "-bad.com", "bad-.com", "exa mple.com", "example.c0m",
    "8.8.8.8", "a" * 64 + ".com", "example..com", None, 123, "exam\x00ple.com",
])
def test_invalid_domains(raw):
    with pytest.raises(ValidationError):
        validate_domain(raw)


def test_usernames():
    assert validate_username("@demo_analyst") == "demo_analyst"
    assert validate_username("john.doe-99") == "john.doe-99"
    for bad in ["a", "_start", "has space", "x" * 40, "semi;colon", "../etc", "<script>"]:
        with pytest.raises(ValidationError):
            validate_username(bad)


def test_emails():
    assert validate_email("Alice@Demo-Corp.TEST") == "alice@demo-corp.test"
    for bad in ["no-at-sign", "a@@b.com", "a@b", ".a@b.com", "a..b@c.com", "a b@c.com"]:
        with pytest.raises(ValidationError):
            validate_email(bad)


def test_reputation_targets():
    assert validate_reputation_target("8.8.8.8") == "8.8.8.8"
    assert validate_reputation_target("Example.com") == "example.com"
    url = "https://example.com/login?next=/home"
    assert validate_reputation_target(url) == url
    for bad in ["192.168.1.10", "127.0.0.1", "10.0.0.5", "http://127.0.0.1/admin",
                "http://10.1.2.3:8080/", "ftp://example.com/file", "javascript:alert(1)",
                "https:///nohost"]:
        with pytest.raises(ValidationError):
            validate_reputation_target(bad)


def test_mask_email():
    assert mask_email("alice@demo-corp.test") == "a***@demo-corp.test"


@pytest.mark.parametrize("raw, expected", [
    ("alice@demo-corp.test", "email"),
    ("https://phish-login.demo-corp.test/login", "reputation"),
    ("8.8.8.8", "reputation"),
    ("2001:4860:4860::8888", "reputation"),
    ("192.168.1.10", "reputation"),          # detected, then rejected by the validator
    ("demo-corp.test", "domain"),
    ("www.example.com/", "domain"),
    ("@demo_analyst", "username"),
    ("ghost_user_404", "username"),
    ("", None), ("   ", None), (None, None), (42, None), ("has space", None),
    ("<script>", None),
])
def test_detect_scan_type(raw, expected):
    assert detect_scan_type(raw) == expected
