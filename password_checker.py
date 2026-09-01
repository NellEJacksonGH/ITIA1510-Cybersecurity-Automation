# This collects the name of the account or system the password is for (e.g., "Email", "SSH server", "VPN").
## account is the variable, = assigns a value, input() is the function, and "Account or system: " is the argument.
account = input("Account or system: ")

# This collects the username of the account or system. -- (Not used for security checks until Week 02.)
## username is the variable, = assigns a value, input() is the function, and "Username: " is the argument.
username = input("Username: ")

# This collects the password of the account or system.
## password is the variable, = assigns a value, input() is the function, and "Password: " is the argument.
password = input("Password: ")

# This collects how often the password will be changed using units of months.
## rotation_interval is the variable, = assigns a value, int() converts the input to an integer, input() is the function, and "Password rotation interval (months): " is the argument.
rotation_interval = int(input("Password rotation interval (months): "))

# This finds the number of characters in the password using len().
## password_length is the variable, = assigns a value, len() is the function, and password is the argument. len() returns the number of characters in the password.
password_length = len(password)

# This creates the raw numeric strength indicator based on the password length. -- (Not used for classification until Week 02.)
## length_score is the variable, = assigns a value, * is the multiplication operator, password_length is the value being multiplied, and 10 is the integer it is multiplied by.
length_score = password_length * 10

# This uses floor division because only complete password rotations during the 36-month period should be counted.
## rotation_count is the variable, = assigns a value, // is the floor division operator, 36 represents the number of months in 3 years, and rotation_interval is the number it is divided by.
rotation_count = 36 // rotation_interval
# Classify the password based on its length.
if password_length < 8:
    length_verdict = "WEAK -- does not meet minimum length requirements"
elif password_length <= 11:
    length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
elif password_length <= 14:
    length_verdict = "GOOD -- acceptable length for most systems"
else:
    length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"

# Check whether the password contains at least one digit.
has_digit = '0' in password or '1' in password or '2' in password or '3' in password or '4' in password or '5' in password or '6' in password or '7' in password or '8' in password or '9' in password

# Check that the password does not match the username.
not_username = password != username

# Classify the password rotation interval.
if rotation_interval > 12:
    rotation_verdict = "WARNING -- rotation interval exceeds recommended maximum of 12 months"
elif rotation_interval >= 6:
    rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"
else:
    rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

# Check whether the password is at least 15 characters long.
length_ok = password_length >= 15

# The password passes only if it is long enough, contains a digit, and does not match the username.
overall_pass = length_ok and has_digit and not_username
# This displays the completed password audit report using the information and calculations from above.
## print() is the function used to display the text and calculated values in the console. f-strings allow the variables inside {} to be inserted into the output.
print("========================================")
print("   PASSWORD AUDIT REPORT")
print("========================================")
print("Account:           " + account)
print("Username:          " + username)
print("Password length:   " + str(password_length) + " characters")
print("Length score:      " + str(length_score) + " points")
print("Rotation interval: " + str(rotation_interval) + " months")
print("Rotations (3 yr):  " + str(rotation_count))
print("----------------------------------------")
print("Length verdict:    " + length_verdict)

if has_digit:
    print("Digit found:       YES")
else:
    print("Digit found:       NO")

if not_username:
    print("Username match:    NO")
else:
    print("Username match:    YES")
    print("CRITICAL -- password must not match username.")

print("Rotation verdict:  " + rotation_verdict)
print("----------------------------------------")

if overall_pass:
    print("OVERALL: PASS -- password meets all checked criteria")
else:
    print("OVERALL: FAIL -- see findings above")

print("========================================")