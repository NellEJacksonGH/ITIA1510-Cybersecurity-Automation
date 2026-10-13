
# Security rules shared by the password checks and tests.
policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True
}


def check_length(password, policy):
    """Check password length and return its verdict."""
    password_length = len(password)

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
    """Check whether the password contains a digit."""
    has_digit = False

    for char in password:
        if char in '0123456789':
            has_digit = True

    return has_digit


def check_username(password, username):
    """Check whether the password differs from the username."""
    not_username = password != username
    return not_username


def check_rotation(rotation_interval, policy):
    """Check password rotation using the policy dictionary."""
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
    """Check whether a password is not in the breach list."""
    not_breached = password not in known_breached
    return not_breached


# Week 07: Read breached passwords from a text file.
def load_breached(filepath):
    """Read the breached password file. Returns a list of password strings."""
    known_breached = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line != "":
                known_breached.append(line)

    return known_breached


# Week 07: Read credentials from a text file.
def load_credentials(filepath):
    """Read credentials and return a list of dictionaries."""
    credentials = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Skip blank lines.
            if line == "":
                continue

            fields = line.split(",")

            credentials.append({
                "account": fields[0],
                "username": fields[1],
                "password": fields[2],
                "rotation_interval": int(fields[3]),
            })

    return credentials


# Week 07: Save report lines to a text file.
def write_report(report_lines, filepath):
    """Write each string in report_lines to the file as one line."""
    with open(filepath, "w") as f:
        for line in report_lines:
            f.write(line + "\n")


def audit_password(account, username, password, rotation_interval,
                   known_breached, policy, report_lines):
    """Audit one password and collect the report in report_lines."""

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    # Existing Week 06 password checks.
    length_ok, length_verdict = check_length(password, policy)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval, policy)
    not_breached = check_breach(password, known_breached)

    digit_requirement_met = has_digit or not policy["require_digit"]
    breach_requirement_met = not_breached or not policy["check_breach_list"]

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

    if not_username and breach_requirement_met:
        critical = 0
    else:
        critical = 1

    # Week 07: Collect report lines instead of printing immediately.
    report_lines.append("========================================")
    report_lines.append("   PASSWORD AUDIT REPORT")
    report_lines.append("========================================")
    report_lines.append("Account:           " + account)
    report_lines.append("Username:          " + username)
    report_lines.append("Password length:   " + str(password_length) + " characters")
    report_lines.append("Length score:      " + str(length_score) + " points")
    report_lines.append("Rotation interval: " + str(rotation_interval) + " months")
    report_lines.append("Rotations (3 yr):  " + str(rotation_count))
    report_lines.append("----------------------------------------")
    report_lines.append("Length verdict:    " + length_verdict)

    if has_digit:
        report_lines.append("Digit found:       YES")
    else:
        report_lines.append("Digit found:       NO")

    if not_username:
        report_lines.append("Username match:    NO")
    else:
        report_lines.append("Username match:    YES")
        report_lines.append("CRITICAL -- password must not match username.")

    if not_breached:
        report_lines.append("Breach check:      PASS -- password not found in known breach list")
    else:
        report_lines.append("Breach check:      CRITICAL -- password found in known breach list")

    report_lines.append("Rotation verdict:  " + rotation_verdict)
    report_lines.append("----------------------------------------")

    if overall_pass:
        report_lines.append("OVERALL: PASS -- password meets all checked criteria")
    else:
        report_lines.append("OVERALL: FAIL -- see findings above")

    report_lines.append("========================================")
    report_lines.append("")

    return passed, failed, critical


if __name__ == '__main__':

    # Week 07: Load data from files instead of hardcoded lists.
    credentials = load_credentials("credentials.txt")
    known_breached = load_breached("breached.txt")
    report_lines = []

    # Keep the Week 06 summary dictionary.
    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": []
    }

    for cred in credentials:

        passed, failed, critical = audit_password(
            cred["account"],
            cred["username"],
            cred["password"],
            cred["rotation_interval"],
            known_breached,
            policy,
            report_lines
        )

        summary["total"] += 1
        summary["passed"] += passed
        summary["failed"] += failed
        summary["critical"] += critical

        if failed:
            summary["failed_accounts"].append(cred["account"])

        if critical:
            summary["critical_accounts"].append(cred["account"])

    # Collect the batch summary.
    report_lines.append("========================================")
    report_lines.append("   BATCH AUDIT SUMMARY")
    report_lines.append("========================================")
    report_lines.append("Credentials audited: " + str(summary["total"]))
    report_lines.append("Passed:              " + str(summary["passed"]))
    report_lines.append("Failed:              " + str(summary["failed"]))
    report_lines.append("----------------------------------------")

    if summary["failed_accounts"]:
        report_lines.append("Failed accounts:     " + ", ".join(summary["failed_accounts"]))
    else:
        report_lines.append("Failed accounts:     None")

    report_lines.append("Critical flags:      " + str(summary.get("critical", 0)))

    if summary["critical_accounts"]:
        report_lines.append("Critical accounts:   " + ", ".join(summary["critical_accounts"]))
    else:
        report_lines.append("Critical accounts:   None")

    report_lines.append("========================================")

    # Week 07: Display and save the exact same report.
    for line in report_lines:
        print(line)

    write_report(report_lines, "report.txt")