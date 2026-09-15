def check_length(password):
    """Checks password length and returns whether it meets the 15-character requirement and its verdict."""

    password_length = len(password)

    if password_length < 8:
        length_ok = False
        length_verdict = "WEAK -- does not meet minimum length requirements"
    elif password_length <= 11:
        length_ok = False
        length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
    elif password_length <= 14:
        length_ok = False
        length_verdict = "GOOD -- acceptable length for most systems"
    else:
        length_ok = True
        length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"

    return length_ok, length_verdict


def check_digit(password):
    """Checks whether the password contains a digit and returns True or False."""

    # Check each character for a digit using the Week 3 loop method.
    has_digit = False

    for char in password:
        if char in '0123456789':
            has_digit = True

    return has_digit


def check_username(password, username):
    """Checks whether the password is different from the username and returns True or False."""

    not_username = password != username

    return not_username


def check_rotation(rotation_interval):
    """Checks the password rotation interval and returns whether it is acceptable and its verdict."""

    if rotation_interval > 12:
        rotation_ok = False
        rotation_verdict = "WARNING -- rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= 6:
        rotation_ok = True
        rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"
    else:
        rotation_ok = True
        rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

    return rotation_ok, rotation_verdict


def audit_password(account, username, password, rotation_interval):
    """Audits one password, prints the full report, and returns pass, fail, and critical counters."""

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    # Call the four separate functions to get the password check results.
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)

    # All three required password conditions must be true for an overall pass.
    overall_pass = length_ok and has_digit and not_username

    if overall_pass:
        passed = 1
        failed = 0
    else:
        passed = 0
        failed = 1

    # A password that matches the username is counted as a critical flag.
    if not_username:
        critical = 0
    else:
        critical = 1

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
    print()

    return passed, failed, critical


if __name__ == '__main__':
    # This keeps the input loop from running when the functions are imported by the test file.
    batch_size = 3
    count = 0
    total_pass = 0
    total_fail = 0
    critical_count = 0

    while count < batch_size:

        # Collect information for the current password.
        account = input("Enter account: ")
        username = input("Enter username: ")
        password = input("Enter password: ")
        rotation_interval = int(input("Enter password rotation interval in months: "))

        # Run the audit function and add its results to the batch totals.
        passed, failed, critical = audit_password(
            account, username, password, rotation_interval
        )

        total_pass += passed
        total_fail += failed
        critical_count += critical

        count += 1

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