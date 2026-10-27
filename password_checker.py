
import json
import os

# Security rules are shared by the password checks and tests.
policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True,
    "history_runs": 3
}


def check_length(password, policy):
    """Check password length using the security policy."""
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
        if char in "0123456789":
            has_digit = True

    return has_digit


def check_username(password, username):
    """Check whether the password differs from the username."""
    return password != username


def check_rotation(rotation_interval, policy):
    """Check the password rotation interval."""
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
    """Check whether a password is absent from the breach list."""
    return password not in known_breached


def load_breached(filepath):
    """Load breached passwords from a text file."""
    known_breached = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line != "":
                known_breached.append(line)

    return known_breached


def load_credentials(filepath):
    """Load credentials from a CSV-style text file."""
    credentials = []

    with open(filepath, "r") as f:
        for line in f:
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
    """Write the audit report to a text file."""
    with open(filepath, "w") as f:
        for line in report_lines:
            f.write(line + "\n")


def save_summary(summary, filepath):
    """Save the latest audit summary as JSON."""
    with open(filepath, "w") as f:
        json.dump(summary, f, indent=2)


def load_summary(filepath):
    """Load an existing audit summary from JSON."""
    with open(filepath, "r") as f:
        return json.load(f)


# Week 10: Load previous audit runs.
def load_history(filepath):
    # A missing file means this is the first audit, so start with an empty list.
    if not os.path.exists(filepath):
        return []

    with open(filepath, "r") as f:
        return json.load(f)


# Week 10: Add one audit run and keep the newest entries.
def add_to_history(history, summary, keep):
    # Use the newest run number, not len(history), because trimming changes the list length.
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

    # Trim the history so it keeps only the newest runs and does not grow forever.
    return history[-keep:]


# Week 10: Save the updated history to JSON.
def save_history(history, filepath):
    with open(filepath, "w") as f:
        json.dump(history, f, indent=2)


def audit_password(account, username, password, rotation_interval,
                   known_breached, policy, report_lines):
    """Audit one password and return pass, fail, and critical counters."""

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


if __name__ == "__main__":
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

    report_lines.append("Critical flags:      " + str(summary["critical"]))

    if summary["critical_accounts"]:
        report_lines.append("Critical accounts:   " + ", ".join(summary["critical_accounts"]))
    else:
        report_lines.append("Critical accounts:   None")

    report_lines.append("========================================")

    for line in report_lines:
        print(line)

    write_report(report_lines, "report.txt")
    save_summary(summary, "audit_summary.json")

    # Week 10: Update the audit history without printing extra output.
    history = load_history("audit_history.json")
    history = add_to_history(history, summary, policy["history_runs"])
    save_history(history, "audit_history.json")