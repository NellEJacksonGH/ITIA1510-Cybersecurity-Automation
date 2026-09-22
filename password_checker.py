# This list is outside the main block so the functions and test file can import and use it.
known_breached = [
    "password",
    "password123",
    "123456",
    "qwerty",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "sunshine"
]


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

    # A for loop walks through each character, while "in" can directly check membership in a list.
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


def check_breach(password, known_breached):
    """Checks whether a password is not in the known breached password list."""

    not_breached = password not in known_breached

    return not_breached


def audit_password(account, username, password, rotation_interval, known_breached):
    """Audits one password, prints the full report, and returns pass, fail, and critical counters."""

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    # Call the password-checking functions to get each result.
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)
    not_breached = check_breach(password, known_breached)

    # All four required conditions must be true for an overall pass.
    overall_pass = length_ok and has_digit and not_username and not_breached

    if overall_pass:
        passed = 1
        failed = 0
    else:
        passed = 0
        failed = 1

    # A password is critical if it matches the username or appears in the breach list.
    if not_username and not_breached:
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

    if not_breached:
        print("Breach check:      PASS -- password not found in known breach list")
    else:
        print("Breach check:      CRITICAL -- password found in known breach list")

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
    # These credential records replace the interactive input loop from previous weeks.
    credentials = [
        ["Gmail", "jsmith", "password123", 12],
        ["SSH Server", "jsmith", "jsmith", 24],
        ["VPN", "jsmith", "Tr0ub4dor&3correct", 3],
        ["Company Email", "jsmith", "summer2024!", 6],
        ["GitHub", "jsmith", "Blue-Harbor-72-Lantern", 6],
    ]

    # These lists store account names that fail or receive a critical flag.
    failed_accounts = []
    critical_accounts = []

    # Loop through each credential record and audit it.
    for credential in credentials:

        # Get each value from the credential record by index.
        account = credential[0]
        username = credential[1]
        password = credential[2]
        rotation_interval = credential[3]

        # Run the audit and receive the pass, fail, and critical results.
        passed, failed, critical = audit_password(
            account,
            username,
            password,
            rotation_interval,
            known_breached
        )

        # Add failed accounts to the failed_accounts list.
        if failed:
            failed_accounts.append(account)

        # Add critical accounts to the critical_accounts list.
        if critical:
            critical_accounts.append(account)

    print("========================================")
    print("   BATCH AUDIT SUMMARY")
    print("========================================")
    print("Credentials audited: " + str(len(credentials)))
    print("Passed:              " + str(len(credentials) - len(failed_accounts)))
    print("Failed:              " + str(len(failed_accounts)))
    print("----------------------------------------")

    if failed_accounts:
        print("Failed accounts:     " + ", ".join(failed_accounts))
    else:
        print("Failed accounts:     None")

    print("Critical flags:      " + str(len(critical_accounts)))

    if critical_accounts:
        print("Critical accounts:   " + ", ".join(critical_accounts))
    else:
        print("Critical accounts:   None")

    print("----------------------------------------")
    print("NOTE: Breach list and credentials are hardcoded -- file reading coming in Week 08.")
    print("========================================")