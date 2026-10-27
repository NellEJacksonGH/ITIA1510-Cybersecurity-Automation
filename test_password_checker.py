
from password_checker import (
    check_length,
    check_digit,
    check_username,
    check_rotation,
    check_breach,
    load_credentials,
    load_breached,
    write_report,
    save_summary,
    load_summary,
    load_history,
    add_to_history,
    save_history,
    policy
)

import json

known_breached = load_breached("breached.txt")


# Tests retained from Weeks 04 through 06.
length_ok, length_verdict = check_length("test", policy)
assert length_ok is False
print("PASS: check_length() returns False for a short password")

length_ok, length_verdict = check_length("Blue-Harbor-72-Lantern", policy)
assert length_ok is True
print("PASS: check_length() returns True for a strong password")

assert check_digit("password") is False
print("PASS: check_digit() returns False when no digit is present")

assert check_digit("password123") is True
print("PASS: check_digit() returns True when a digit is present")

assert check_username("jsmith", "jsmith") is False
print("PASS: check_username() returns False when password matches username")

assert check_username("Blue-Harbor-72-Lantern", "jsmith") is True
print("PASS: check_username() returns True when password differs from username")

rotation_ok, rotation_verdict = check_rotation(6, policy)
assert rotation_ok is True
print("PASS: check_rotation() returns True for 6 months")

rotation_ok, rotation_verdict = check_rotation(24, policy)
assert rotation_ok is False
print("PASS: check_rotation() returns False for 24 months")

assert check_breach("password123", known_breached) is False
print("PASS: check_breach() returns False for a breached password")

assert check_breach("Blue-Harbor-72-Lantern", known_breached) is True
print("PASS: check_breach() returns True for a password not in the breach list")

assert policy["strong_length"] == 15
print("PASS: policy strong_length is 15")

assert "require_digit" in policy
print("PASS: require_digit exists in policy")

assert policy["min_length"] == 8
print("PASS: policy min_length is 8")

assert policy["max_rotation_months"] == 12
print("PASS: policy max_rotation_months is 12")


# Week 07 tests.
credentials = load_credentials("credentials.txt")
assert isinstance(credentials, list)
print("PASS: load_credentials() returns a list")

assert "account" in credentials[0]
print("PASS: first credential has an account key")

assert isinstance(known_breached, list)
print("PASS: load_breached() returns a list")

assert "password123" in known_breached
print("PASS: load_breached() includes password123")

write_report(["first line", "second line"], "test_report.txt")

with open("test_report.txt", "r") as f:
    saved_report = f.read()

assert saved_report == "first line\nsecond line\n"
print("PASS: write_report() saves two lines correctly")


# Week 09 JSON tests.
def test_save_summary(tmp_path):
    filepath = tmp_path / "summary.json"
    sample = {
        "total": 5,
        "passed": 2,
        "failed": 3,
        "critical": 2,
        "failed_accounts": ["Gmail", "SSH Server", "Company Email"],
        "critical_accounts": ["Gmail", "SSH Server"]
    }

    save_summary(sample, filepath)

    with open(filepath, "r") as f:
        loaded = json.load(f)

    assert loaded == sample
    print("PASS: save_summary writes JSON correctly")


def test_load_summary(tmp_path):
    filepath = tmp_path / "summary.json"
    sample = {
        "passed": 2,
        "failed": 3,
        "critical_accounts": ["Gmail", "SSH Server"]
    }

    with open(filepath, "w") as f:
        json.dump(sample, f)

    assert load_summary(filepath) == sample
    print("PASS: load_summary reads JSON correctly")


# Week 10 tests.
def test_load_history_missing(tmp_path):
    filepath = tmp_path / "missing.json"

    assert load_history(filepath) == []
    print("PASS: missing history returns empty list")


def test_add_to_history_first_run():
    sample = {
        "passed": 2,
        "failed": 3,
        "critical_accounts": ["Gmail", "SSH Server"]
    }

    history = add_to_history([], sample, 3)

    assert len(history) == 1
    assert history[0]["run"] == 1
    assert history[0]["passed"] == 2
    assert history[0]["failed"] == 3
    assert history[0]["critical_accounts"] == ["Gmail", "SSH Server"]

    print("PASS: first history entry is run 1")


def test_add_to_history_trims():
    sample = {
        "passed": 2,
        "failed": 3,
        "critical_accounts": ["Gmail", "SSH Server"]
    }

    history = []

    for i in range(3):
        history = add_to_history(history, sample, 2)

    assert [entry["run"] for entry in history] == [2, 3]
    print("PASS: add_to_history kept only the newest 2 runs")


def test_save_and_load_history(tmp_path):
    filepath = tmp_path / "history.json"

    history = [{
        "run": 1,
        "passed": 2,
        "failed": 3,
        "critical_accounts": ["Gmail", "SSH Server"]
    }]

    save_history(history, filepath)
    loaded = load_history(filepath)

    assert loaded == history
    print("PASS: saved history loads correctly")


if __name__ == "__main__":
    test_save_summary(__import__("pathlib").Path("."))
    test_load_summary(__import__("pathlib").Path("."))
    test_load_history_missing(__import__("pathlib").Path("."))
    test_add_to_history_first_run()
    test_add_to_history_trims()
    test_save_and_load_history(__import__("pathlib").Path("."))
    print("ALL TESTS PASSED")