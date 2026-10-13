
from password_checker import (
    check_length,
    check_digit,
    check_username,
    check_rotation,
    check_breach,
    load_credentials,
    load_breached,
    write_report,
    policy
)

# Week 07: Load the breach list from the text file.
known_breached = load_breached("breached.txt")


# Test check_length()
length_ok, length_verdict = check_length("test", policy)
assert length_ok is False
print("PASS: check_length() returns False for a short password")

length_ok, length_verdict = check_length("Blue-Harbor-72-Lantern", policy)
assert length_ok is True
print("PASS: check_length() returns True for a strong password")


# Test check_digit()
assert check_digit("password") is False
print("PASS: check_digit() returns False when no digit is present")

assert check_digit("password123") is True
print("PASS: check_digit() returns True when a digit is present")


# Test check_username()
assert check_username("jsmith", "jsmith") is False
print("PASS: check_username() returns False when password matches username")

assert check_username("Blue-Harbor-72-Lantern", "jsmith") is True
print("PASS: check_username() returns True when password differs from username")


# Test check_rotation()
rotation_ok, rotation_verdict = check_rotation(6, policy)
assert rotation_ok is True
print("PASS: check_rotation() returns True for 6 months")

rotation_ok, rotation_verdict = check_rotation(24, policy)
assert rotation_ok is False
print("PASS: check_rotation() returns False for 24 months")


# Test check_breach()
assert check_breach("password123", known_breached) is False
print("PASS: check_breach() returns False for a breached password")

assert check_breach("Blue-Harbor-72-Lantern", known_breached) is True
print("PASS: check_breach() returns True for a password not in the breach list")


# Week 06 policy dictionary tests.
assert policy["strong_length"] == 15
print("PASS: policy strong_length is 15")

assert "require_digit" in policy
print("PASS: require_digit exists in policy")

assert policy["min_length"] == 8
print("PASS: policy min_length is 8")

assert policy["max_rotation_months"] == 12
print("PASS: policy max_rotation_months is 12")


# Week 07: Test load_credentials()
credentials = load_credentials("credentials.txt")

assert isinstance(credentials, list)
print("PASS: load_credentials() returns a list")

assert "account" in credentials[0]
print("PASS: first credential contains an account key")


# Week 07: Test load_breached()
assert isinstance(known_breached, list)
print("PASS: load_breached() returns a list")

assert "password123" in known_breached
print("PASS: load_breached() contains password123")


# Week 07: Test write_report()
write_report(["first line", "second line"], "test_report.txt")

with open("test_report.txt", "r") as f:
    saved_report = f.read()

assert saved_report == "first line\nsecond line\n"
print("PASS: write_report() saves two lines correctly")


print("ALL TESTS PASSED")
