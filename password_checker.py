# Collect the account or system the password is for.
account = input("Account or system: ")

# Collect the username now because future weeks will use it
# for additional password security checks.
username = input("Username: ")

# Collect the password that will be analyzed.
password = input("Password: ")

# Collect the rotation interval as a string, then convert it to an integer.
rotation_interval = int(input("Password rotation interval (months): "))

# Calculate the length of the password.
password_length = len(password)

# Calculate the raw strength score based on password length.
length_score = password_length * 10

# Calculate how many times the password will be rotated over three years.
rotation_count = 36 // rotation_interval

# Display the password audit report.
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
