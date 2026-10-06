from password_checker import (
    check_length,
    check_digit,
    check_username,
    check_rotation,
    check_breach,
    known_breached,
    policy
)


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


# Week 06 policy dictionary tests
assert policy["strong_length"] == 15
print("PASS: policy strong_length is 15")

assert "require_digit" in policy
print("PASS: require_digit exists in policy")

assert policy["min_length"] == 8
print("PASS: policy min_length is 8")

assert policy["max_rotation_months"] == 12
print("PASS: policy max_rotation_months is 12")


print("ALL TESTS PASSED")