import pytest

import validators


@pytest.mark.parametrize("password, fragment", [
    ("short1", "at least 10"),
    ("password123", "too common"),
    ("Passw0rd!!", "too common"),    # a trailing-digit variant of a listed password
    ("Tr0ub4dor&3x", None),
    ("aaaaaaaaaaaa", "distinct"),
    ("x" * 80, "bytes"),
    ("my ada_l secret 99", "username"),
])
def test_password_rules(password, fragment):
    problem = validators.check_password(password, "ada_l")
    if fragment is None:
        assert problem is None
    else:
        assert fragment in problem


def test_multibyte_password_counts_bytes_not_characters():
    # 40 characters but 80 bytes: over bcrypt's 72 byte limit
    assert "bytes" in validators.check_password("é" * 40)


@pytest.mark.parametrize("raw, clean", [
    ("+1 (555) 123-4567", "+15551234567"),
    ("+44 7700 900123", "+447700900123"),
    ("  +91-98765-43210 ", "+919876543210"),
])
def test_phone_normalisation(raw, clean):
    assert validators.normalize_phone(raw) == clean
    assert validators.check_phone(clean) is None


@pytest.mark.parametrize("phone", ["5551234567", "+0123456789", "+12", "+1555abc4567", ""])
def test_phone_needs_country_code(phone):
    assert validators.check_phone(phone)


@pytest.mark.parametrize("name, ok", [
    ("ada", True), ("ada_l.99", True), ("ab", False), ("a b c", False), ("x" * 33, False),
])
def test_usernames(name, ok):
    assert (validators.check_username(name) is None) is ok
