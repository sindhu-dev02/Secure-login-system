import re

from users import MAX_PASSWORD_BYTES

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PHONE_RE = re.compile(r"^\+[1-9]\d{7,14}$")  # E.164

MIN_PASSWORD_LENGTH = 10

# Not exhaustive. Catches the passwords people reach for first.
COMMON_PASSWORDS = frozenset("""
    password passw0rd p@ssw0rd qwerty qwertyuiop qwerty123 asdfghjkl zxcvbnm
    letmein welcome iloveyou admin administrator login changeme secret
    monkey dragon football baseball master shadow sunshine princess superman
    trustno1 abc123 abcdefg 1q2w3e4r 1qaz2wsx qazwsx abcd1234 starwars
""".split())


def normalize_phone(raw):
    """Drop the spaces, dashes and brackets people type into phone numbers."""
    return re.sub(r"[\s().-]", "", raw or "")


def check_username(name):
    if not USERNAME_RE.match(name):
        return "Usernames are 3-32 characters: letters, numbers, dot, dash, underscore."
    return None


def check_phone(phone):
    if not PHONE_RE.match(phone):
        return "Enter the number with its country code, like +15551234567."
    return None


def check_password(passw, username=""):
    if len(passw) < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters."
    if len(passw.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return f"Keep the password under {MAX_PASSWORD_BYTES} bytes."
    lowered = passw.lower()
    if lowered in COMMON_PASSWORDS or lowered.rstrip("0123456789!") in COMMON_PASSWORDS:
        return "That password is too common."
    if len(set(passw)) < 5:
        return "That password repeats too few distinct characters."
    if len(username) >= 3 and username.lower() in lowered:
        return "The password shouldn't contain your username."
    return None


def check_registration(name, passw, phone):
    """Return a list of problems; an empty list means the input is acceptable."""
    checks = (
        check_username(name),
        check_password(passw, name),
        check_phone(phone),
    )
    return [problem for problem in checks if problem]
