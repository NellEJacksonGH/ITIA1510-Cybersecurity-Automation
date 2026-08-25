# This collects the name of the account or system the password is for (e.g., "Email", "SSH server", "VPN").
## account is the variable, = assigns a value, input() is the function, and "Account or system: " is the argument.
account = input("Account or system: ")

# This collects the username of the account or system. -- (Wont be used for security checks until Week 02.)
## username is the variable, = assigns a value, input() is the function, and "Username: " is the argument.
username = input("Username: ")

# Collect the password that will be analyzed by the account or system.
## password is the variable, = assigns a value, input() is the function, and "Password: " is the argument.
password = input("Password: ")

# Collect the rotation interval as a string, then convert it to an integer.
## rotation_interval is the variable, = assigns a value, int() converts the input to an integer, input() is the function, and "Password rotation interval (months): " is the argument.
rotation_interval = int(input("Password rotation interval (months): "))

# Calculate the length of the password.
## password_length is the variable, = assigns a value, len() is the function, and password is the argument. len() returns the number of characters in the password.
password_length = len(password)

# Calculate the raw strength score based on password length.
## length_score is the variable, = assigns a value, * is the multiplication operator, password_length is the value being multiplied, and 10 is the integer it is multiplied by.
length_score = password_length * 10

# Calculate how many times the password will be rotated over three years.
## rotation_count is the variable, = assigns a value, // is the floor division operator, 36 represents the number of months in 3 years, and rotation_interval is the number it is divided by.
rotation_count = 36 // rotation_interval

# This displays the completed password audit report using the information and calculations from above.
## print() is the function used to display the text and calculated values in the console. f-strings allow the variables inside {} to be inserted into the output.
print("========================================")
print("   PASSWORD AUDIT REPORT")
print("========================================")
print(f"Account:           {account}")
print(f"Username:          {username}")
print(f"Password length:   {password_length} characters")
print(f"Length score:      {length_score} points")
print(f"Rotation interval: {rotation_interval} months")
print(f"Rotations (3 yr):  {rotation_count}")
print("----------------------------------------")
print("NOTE: Classification requires conditionals -- coming in Week 02.")
print("========================================")
