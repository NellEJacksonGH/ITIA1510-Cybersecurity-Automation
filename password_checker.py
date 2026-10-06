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


# Policy is outside the main block so functions and the test file can import
# and use the same security rules.
policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True
}


def check_length(password, policy):
    """Checks password length and returns whether it meets the strong-length requirement and its verdict."""

    password_length = len(password)

    # Reading limits from policy is better than hardcoding them because
    # changing the rule in one place updates every function that uses it.
    if password_length < policy["min_length"]:
        length_ok = False
        length_verdict = "WEAK -- does not meet minimum length requirements"
    elif password_length <= 11:
        length_ok = False
        length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
    elif password_length < policy["strong_length"]:
        length_ok = False
        length_verdict = "GOOD -- acceptable length for most systems"
    else:
        length_ok = True
        length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"

    return length_ok, length_verdict


def check_digit(password):
    """Checks whether the password contains a digit and returns True or False."""

    # A for loop walks through each character of the password.
    has_digit = False

    for char in password:
        if char in '0123456789':
            has_digit = True

    return has_digit


def check_username(password, username):
    """Checks whether the password is different from the username and returns True or False."""

    not_username = password != username

    return not_username


def check_rotation(rotation_interval, policy):
    """Checks the password rotation interval using the policy dictionary."""

    if rotation_interval > policy["max_rotation_months"]:
        rotation_ok = False
        rotation_verdict = "WARNING -- rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= policy["good_rotation_months"]:
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


def audit_password(account, username, password, rotation_interval,
                   known_breached, policy):
    """Audits one password, prints the full report, and returns pass, fail, and critical counters."""

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    # Call the password-checking functions and pass policy where needed.
    length_ok, length_verdict = check_length(password, policy)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval, policy)
    not_breached = check_breach(password, known_breached)

    # These policy settings control whether digit and breach checks are required.
    digit_requirement_met = has_digit or not policy["require_digit"]
    breach_requirement_met = not_breached or not policy["check_breach_list"]

    # All required conditions must be true for an overall pass.
    overall_pass = (
        length_ok
        and digit_requirement_met
        and not_username
        and breach_requirement_met
    )

    if overall_pass:
        passed = 1
        failed = 0
    else:
        passed = 0
        failed = 1

    # A password is critical if it matches the username or is on the breach list.
    if not_username and breach_requirement_met:
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

    # Each credential is now a dictionary, so values are read by key name
    # instead of depending on their position inside a list.
    credentials = [
        {
            "account": "Gmail",
            "username": "jsmith",
            "password": "password123",
            "rotation_interval": 12
        },
        {
            "account": "SSH Server",
            "username": "jsmith",
            "password": "jsmith",
            "rotation_interval": 24
        },
        {
            "account": "VPN",
            "username": "jsmith",
            "password": "Tr0ub4dor&3correct",
            "rotation_interval": 3
        },
        {
            "account": "Company Email",
            "username": "jsmith",
            "password": "summer2024!",
            "rotation_interval": 6
        },
        {
            "account": "GitHub",
            "username": "jsmith",
            "password": "Blue-Harbor-72-Lantern",
            "rotation_interval": 6
        }
    ]

    # One dictionary now stores all batch counters and account-name lists.
    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": []
    }

    # Loop through each credential dictionary.
    for cred in credentials:

        # Read credential values by their key names instead of index positions.
        passed, failed, critical = audit_password(
            cred["account"],
            cred["username"],
            cred["password"],
            cred["rotation_interval"],
            known_breached,
            policy
        )

        # Update all batch totals inside the summary dictionary.
        summary["total"] += 1
        summary["passed"] += passed
        summary["failed"] += failed
        summary["critical"] += critical

        if failed:
            summary["failed_accounts"].append(cred["account"])

        if critical:
            summary["critical_accounts"].append(cred["account"])

    print("========================================")
    print("   BATCH AUDIT SUMMARY")
    print("========================================")
    print("Credentials audited: " + str(summary["total"]))
    print("Passed:              " + str(summary["passed"]))
    print("Failed:              " + str(summary["failed"]))
    print("----------------------------------------")

    if summary["failed_accounts"]:
        print("Failed accounts:     " + ", ".join(summary["failed_accounts"]))
    else:
        print("Failed accounts:     None")

    # .get() safely returns 0 if the critical key is ever missing.
    print("Critical flags:      " + str(summary.get("critical", 0)))

    if summary["critical_accounts"]:
        print("Critical accounts:   " + ", ".join(summary["critical_accounts"]))
    else:
        print("Critical accounts:   None")

    print("----------------------------------------")
    print("NOTE: Credentials and breach list are hardcoded -- file reading coming in Week 07.")
    print("========================================")