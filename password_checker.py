
import json
import os


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
    """Check whether a password contains a digit."""
    has_digit = False

    for char in password:
        if char in "0123456789":
            has_digit = True

    return has_digit


def check_username(password, username):
    """Check whether the password differs from the username."""
    not_username = password != username
    return not_username


def check_rotation(rotation_interval, policy):
    """Check password rotation against the security policy."""

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
    """Return True if the password is not on the breach list."""
    not_breached = password not in known_breached
    return not_breached


def breach_verdicts(username, credentials, known_breached):
    """Return breach verdicts for one user's accounts without passwords."""

    result = {
        "username": username,
        "accounts": []
    }

    # Only check accounts belonging to the requested username.
    for credential in credentials:
        if credential["username"] == username:

            # check_breach() returns True for a password that is NOT
            # breached, so we reverse its result for on_breach_list.
            on_breach_list = not check_breach(
                credential["password"],
                known_breached
            )

            # Passwords are deliberately excluded to minimize sensitive
            # information exposed to reports or an AI model's history.
            result["accounts"].append({
                "account": credential["account"],
                "on_breach_list": on_breach_list
            })

    return result


def load_breached(filepath):
    """Load known breached passwords from a text file."""
    known_breached = []

    with open(filepath, "r") as file:
        for line in file:
            line = line.strip()

            if line != "":
                known_breached.append(line)

    return known_breached


def load_credentials(filepath):
    """Load credentials from a comma-separated text file."""
    credentials = []

    with open(filepath, "r") as file:
        for line in file:
            line = line.strip()

            if line == "":
                continue

            fields = line.split(",")

            credentials.append({
                "account": fields[0],
                "username": fields[1],
                "password": fields[2],
                "rotation_interval": int(fields[3])
            })

    return credentials


def write_report(report_lines, filepath):
    """Write the password audit report to a text file."""

    with open(filepath, "w") as file:
        for line in report_lines:
            file.write(line + "\n")


def save_summary(summary, filepath="audit_summary.json"):
    """Save the latest audit summary as JSON."""

    with open(filepath, "w") as file:
        json.dump(summary, file, indent=2)


def load_summary(filepath="audit_summary.json"):
    """Load a previously saved audit summary."""

    if not os.path.exists(filepath):
        return {}

    with open(filepath, "r") as file:
        return json.load(file)


def load_history(filepath="audit_history.json"):
    """Load previous audit runs from JSON."""

    if not os.path.exists(filepath):
        return []

    with open(filepath, "r") as file:
        return json.load(file)


def add_to_history(history, summary, history_runs=3):
    """Add the current audit to history, keeping only recent runs."""

    if history:
        run_number = history[-1]["run"] + 1
    else:
        run_number = 1

    entry = {
        "run": run_number,
        "passed": summary["passed"],
        "failed": summary["failed"],
        "critical_accounts": summary["critical_accounts"]
    }

    history.append(entry)

    # Keep only the most recent audit runs.
    return history[-history_runs:]


def save_history(history, filepath="audit_history.json"):
    """Save audit history as formatted JSON."""

    with open(filepath, "w") as file:
        json.dump(history, file, indent=2)


def audit_password(account, username, password, rotation_interval,
                   known_breached, policy, report_lines):
    """Audit one password and return pass, fail, and critical counts."""

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

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
        report_lines.append(
            "Breach check:      PASS -- password not found in known breach list"
        )
    else:
        report_lines.append(
            "Breach check:      CRITICAL -- password found in known breach list"
        )

    report_lines.append("Rotation verdict:  " + rotation_verdict)
    report_lines.append("----------------------------------------")

    if overall_pass:
        report_lines.append(
            "OVERALL: PASS -- password meets all checked criteria"
        )
    else:
        report_lines.append(
            "OVERALL: FAIL -- see findings above"
        )

    report_lines.append("========================================")
    report_lines.append("")

    return passed, failed, critical


if __name__ == "__main__":

    # Load credentials and the known breached password list.
    credentials = load_credentials("credentials.txt")
    known_breached = load_breached("breached.txt")

    report_lines = []

    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": []
    }

    # Audit every credential in the input file.
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

    # Build the batch audit summary.
    report_lines.append("========================================")
    report_lines.append("   BATCH AUDIT SUMMARY")
    report_lines.append("========================================")
    report_lines.append("Credentials audited: " + str(summary["total"]))
    report_lines.append("Passed:              " + str(summary["passed"]))
    report_lines.append("Failed:              " + str(summary["failed"]))
    report_lines.append("----------------------------------------")

    if summary["failed_accounts"]:
        report_lines.append(
            "Failed accounts:     " + ", ".join(summary["failed_accounts"])
        )
    else:
        report_lines.append("Failed accounts:     None")

    report_lines.append("Critical flags:      " + str(summary["critical"]))

    if summary["critical_accounts"]:
        report_lines.append(
            "Critical accounts:   " + ", ".join(summary["critical_accounts"])
        )
    else:
        report_lines.append("Critical accounts:   None")

    report_lines.append("========================================")

    # Display the completed report.
    for line in report_lines:
        print(line)

    # Week 07: Save the text report.
    write_report(report_lines, "report.txt")

    # Week 09: Save the audit summary.
    save_summary(summary, "audit_summary.json")

    # Week 10: Load, update, and save audit history.
    history = load_history("audit_history.json")

    history = add_to_history(
        history,
        summary,
        history_runs=3
    )

    save_history(history, "audit_history.json")

    # Week 11: Generate breach verdicts for jsmith.
    # The result contains account names and verdicts, never passwords.
    verdicts = breach_verdicts(
        "jsmith",
        credentials,
        known_breached
    )

    # Print the verdicts in readable JSON format.
    print("\n========================================")
    print("   BREACH CHECK VERDICTS")
    print("========================================")
    print(json.dumps(verdicts, indent=2))

    # Save the result for the AI harness.
    with open("breach_check.json", "w") as file:
        json.dump(verdicts, file, indent=2)

    print("\nBreach verdicts saved to breach_check.json")