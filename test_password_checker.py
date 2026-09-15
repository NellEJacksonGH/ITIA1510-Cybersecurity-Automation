# Import the four functions from password_checker.py so they can be tested separately.
from password_checker import check_length, check_digit, check_username, check_rotation


# Test check_length() with a password that is too short.
## The function returns length_ok and length_verdict, and length_ok should be False.
length_ok, length_verdict = check_length("test")
assert length_ok == False
print("PASS: check_length correctly returned False for a 4-character password")


# Test check_length() with a password that is long enough to pass.
## A 16-character password meets the minimum requirement, so length_ok should be True.
length_ok, length_verdict = check_length("abcdefghijklmnop")
assert length_ok == True
print("PASS: check_length correctly returned True for a 16-character password")


# Test check_digit() with a password that does not contain a digit.
## No number is present, so has_digit should be False.
has_digit = check_digit("password")
assert has_digit == False
print("PASS: check_digit correctly returned False for a password with no digits")


# Test check_digit() with a password that contains a digit.
## The number 1 is present, so has_digit should be True.
has_digit = check_digit("password1")
assert has_digit == True
print("PASS: check_digit correctly returned True for a password containing a digit")


# Test check_username() when the password matches the username.
## Matching values mean the password is not different from the username, so not_username is False.
not_username = check_username("jsmith", "jsmith")
assert not_username == False
print("PASS: check_username correctly returned False when the password matches the username")


# Test check_username() when the password is different from the username.
## Different values mean not_username should be True.
not_username = check_username("StrongPassword1", "jsmith")
assert not_username == True
print("PASS: check_username correctly returned True when the password and username are different")


# Test check_rotation() with an interval greater than 12 months.
## An 18-month interval is too long, so rotation_ok should be False.
rotation_ok, rotation_verdict = check_rotation(18)
assert rotation_ok == False
print("PASS: check_rotation correctly returned False for an 18-month interval")


# Test check_rotation() with an acceptable interval.
## A 6-month interval is within the allowed range, so rotation_ok should be True.
rotation_ok, rotation_verdict = check_rotation(6)
assert rotation_ok == True
print("PASS: check_rotation correctly returned True for a 6-month interval")


# If the program reaches this line, all eight tests passed without an AssertionError.
print("All 8 tests passed.")