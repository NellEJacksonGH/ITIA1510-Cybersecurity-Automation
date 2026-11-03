
import json

from password_checker import (
    check_length,
    check_digit,
    check_username,
    check_rotation,
    check_breach,
    breach_verdicts,
    load_credentials,
    load_breached,
    write_report,
    policy
)


known_breached = load_breached("breached.txt")


# ========================================
# Tests retained from Weeks 04 through 06
# ========================================

length_ok, length_verdict = check_length("test", policy)
assert length_ok is False
print("PASS: check_length() returns False for a short password")


length_ok, length_verdict = check_length("Blue-Harbor-72-Lantern", policy)
assert length_ok is True
print("PASS: check_length() returns True for a strong password")


assert check_digit("password") is False
print("PASS: check_digit() returns False when no digit is present")


assert check_digit("password123") is True
print("PASS: check_digit() returns True when a digit is present")


assert check_username("jsmith", "jsmith") is False
print("PASS: check_username() returns False when password matches username")


assert check_username("Blue-Harbor-72-Lantern", "jsmith") is True
print("PASS: check_username() returns True when password differs from username")


rotation_ok, rotation_verdict = check_rotation(6, policy)
assert rotation_ok is True
print("PASS: check_rotation() returns True for 6 months")


rotation_ok, rotation_verdict = check_rotation(24, policy)
assert rotation_ok is False
print("PASS: check_rotation() returns False for 24 months")


assert check_breach("password123", known_breached) is False
print("PASS: check_breach() returns False for a breached password")


assert check_breach("Blue-Harbor-72-Lantern", known_breached) is True
print("PASS: check_breach() returns True for a password not in the breach list")


assert policy["strong_length"] == 15
print("PASS: policy strong_length is 15")


assert "require_digit" in policy
print("PASS: require_digit exists in policy")


assert policy["min_length"] == 8
print("PASS: policy min_length is 8")


assert policy["max_rotation_months"] == 12
print("PASS: policy max_rotation_months is 12")


# ========================================
# Week 07 Tests
# ========================================

credentials = load_credentials("credentials.txt")

assert isinstance(credentials, list)
print("PASS: load_credentials() returns a list")


assert "account" in credentials[0]
print("PASS: first credential has an account key")


assert isinstance(known_breached, list)
print("PASS: load_breached() returns a list")


assert "password123" in known_breached
print("PASS: load_breached() includes password123")


write_report(["first line", "second line"], "test_report.txt")

with open("test_report.txt", "r") as file:
    saved_report = file.read()

assert saved_report == "first line\nsecond line\n"
print("PASS: write_report() saves two lines correctly")


# ========================================
# Week 11 Tests - breach_verdicts()
# ========================================

# Test 1: Verify jsmith's Gmail password
# is correctly identified as breached.

result = breach_verdicts(
    "jsmith",
    load_credentials("credentials.txt"),
    known_breached
)

assert result["username"] == "jsmith"

assert result["accounts"][0] == {
    "account": "Gmail",
    "on_breach_list": True
}

print("PASS: breach_verdicts marked the Gmail password as on the breach list")


# Test 2: A username with no accounts
# must return an empty accounts list.

result = breach_verdicts(
    "nobody",
    load_credentials("credentials.txt"),
    known_breached
)

assert result["username"] == "nobody"
assert result["accounts"] == []

print("PASS: breach_verdicts returns an empty list for an unknown username")


# Test 3: Verify that passwords are never
# included in the JSON result.

credentials = load_credentials("credentials.txt")

result = breach_verdicts(
    "jsmith",
    credentials,
    known_breached
)

result_json = json.dumps(result)

# Passwords must be excluded because AI models
# may retain tool results in their conversation history.

for credential in credentials:

    # The SSH Server password matches the username,
    # which legitimately appears in the JSON output.
    if credential["account"] == "SSH Server":
        continue

    assert credential["password"] not in result_json

# Verify that no password field exists in the output.
assert "password" not in result_json.lower()

print("PASS: breach_verdicts does not expose passwords in JSON")


print("ALL TESTS PASSED")