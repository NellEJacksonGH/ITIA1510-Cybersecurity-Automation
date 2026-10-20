
from password_checker import (
    check_length,
    check_digit,
    check_username,
    check_rotation,
    check_breach,
    load_credentials,
    load_breached,
    write_report,
    save_summary,
    load_summary,
    policy
)

known_breached = load_breached("breached.txt")

# Tests retained from Weeks 04 through 06.
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

# Five new Week 07 tests.
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
with open("test_report.txt", "r") as f:
    saved_report = f.read()
assert saved_report == "first line\nsecond line\n"
print("PASS: write_report() saves two lines correctly")


# Week 09 tests for saving and loading JSON summaries.
sample = {
    "total": 2,
    "passed": 1,
    "failed": 1,
    "critical": 1,
    "failed_accounts": ["Gmail"],
    "critical_accounts": ["Gmail"]
}

# Test 1: Saving and loading returns the original dictionary.
save_summary(sample, "test_summary.json")
loaded = load_summary("test_summary.json")

assert loaded == sample
print("PASS: save_summary and load_summary gave back the same dictionary")


# Test 2: Failed accounts must remain a list, not a string.
assert isinstance(loaded["failed_accounts"], list)
print("PASS: failed_accounts is a list")


# Test 3: No passwords from credentials.txt appear in the JSON.
with open("test_summary.json", "r") as f:
    saved_text = f.read()

credentials = load_credentials("credentials.txt")

for cred in credentials:
    assert cred["password"] not in saved_text

print("PASS: no passwords appear in the saved JSON file")


print("ALL TESTS PASSED")