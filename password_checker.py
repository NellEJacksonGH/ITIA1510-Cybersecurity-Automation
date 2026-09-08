# Set the number of passwords to audit in this batch.
batch_size = 3
count = 0

# These counters start at zero so they can track results across the entire batch.
total_pass = 0
total_fail = 0
critical_count = 0

# Process each password until the batch size is reached.
while count < batch_size:

    # Collect information for the current password.
    account = input("Enter account: ")
    username = input("Enter username: ")
    password = input("Enter password: ")
    rotation_interval = int(input("Enter password rotation interval in months: "))

    # Calculate the password length, score, and three-year rotation count.
    password_length = len(password)
    length_score = password_length * 10
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

    # Check each character for a digit instead of listing every digit separately.
    has_digit = False
    for char in password:
        if char in '0123456789':
            has_digit = True

    # Check that the password does not match the username.
    not_username = password != username

    # Classify the password rotation interval.
    if rotation_interval > 12:
        rotation_verdict = "WARNING -- rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= 6:
        rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

    # Check whether the password meets the minimum length requirement.
    length_ok = password_length >= 15

    # All three conditions must be true for the password to pass.
    overall_pass = length_ok and has_digit and not_username

    # Update the batch counters based on the password's results.
    if overall_pass:
        total_pass += 1
    else:
        total_fail += 1

    # Count passwords that match the username as critical flags.
    if not_username == False:
        critical_count += 1

    # Print the full report for the current password.
    print("========================================")
    print("   PASSWORD AUDIT REPORT  (" + str(count + 1) + " of " + str(batch_size) + ")")
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
    print()

    # Increase the count so the loop moves to the next password.
    count += 1


# Print the summary after all passwords have been audited.
print("========================================")
print("   BATCH AUDIT SUMMARY")
print("========================================")
print("Passwords audited: " + str(batch_size))
print("Passed:            " + str(total_pass))
print("Failed:            " + str(total_fail))
print("Critical flags:    " + str(critical_count))
print("----------------------------------------")
print("NOTE: Input is still hardcoded -- file reading coming in Week 08.")
print("========================================")