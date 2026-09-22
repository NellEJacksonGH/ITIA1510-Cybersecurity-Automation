# Import the Week 04 functions plus the new Week 05 breach-check function and breach list.
from password_checker import check_length, check_digit, check_username, check_rotation, check_breach, known_breached


# Test check_length() with a password that is too short.
length_ok, length_verdict = check_length("test")
assert length_ok == False
print("PASS: check_length correctly returned False for a 4-character password")


# Test check_length() with a password that is long enough to pass.
length_ok, length_verdict = check_length("abcdefghijklmnop")
assert length_ok == True
print("PASS: check_length correctly returned True for a 16-character password")


# Test check_digit() with a password that does not contain a digit.
has_digit = check_digit("password")
assert has_digit == False
print("PASS: check_digit correctly returned False for a password with no digits")


# Test check_digit() with a password that contains a digit.
has_digit = check_digit("password1")
assert has_digit == True
print("PASS: check_digit correctly returned True for a password containing a digit")


# Test check_username() when the password matches the username.
not_username = check_username("jsmith", "jsmith")
assert not_username == False
print("PASS: check_username correctly returned False when the password matches the username")


# Test check_username() when the password is different from the username.
not_username = check_username("StrongPassword1", "jsmith")
assert not_username == True
print("PASS: check_username correctly returned True when the password and username are different")


# Test check_rotation() with an interval greater than 12 months.
rotation_ok, rotation_verdict = check_rotation(18)
assert rotation_ok == False
print("PASS: check_rotation correctly returned False for an 18-month interval")


# Test check_rotation() with an acceptable interval.
rotation_ok, rotation_verdict = check_rotation(6)
assert rotation_ok == True
print("PASS: check_rotation correctly returned True for a 6-month interval")


# Test check_breach() with a password that is in the known breached list.
not_breached = check_breach("password", known_breached)
assert not_breached == False
print("PASS: check_breach correctly returned False for a known breached password")


# Test check_breach() with a password that is not in the known breached list.
not_breached = check_breach("Blue-Harbor-72-Lantern", known_breached)
assert not_breached == True
print("PASS: check_breach correctly returned True for a password not in the breach list")


# If the program reaches this line, all ten tests passed without an AssertionError.
print("All 10 tests passed.")