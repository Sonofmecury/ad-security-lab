from pathlib import Path
import json
import unittest

from audit import audit, compare


def fixture(name):
    return json.loads((Path(__file__).parent / "fixtures" / f"{name}.json").read_text())


class AuditTest(unittest.TestCase):
    def test_three_findings_close(self):
        report = compare(fixture("baseline"), fixture("hardened"))
        self.assertTrue(all(row["verified_closed"] for row in report.values()))

    def test_missing_collection_is_unknown(self):
        report = compare(fixture("baseline"), {})
        self.assertTrue(all(row["after"]["status"] == "unknown" for row in report.values()))
        self.assertFalse(any(row["verified_closed"] for row in report.values()))

    def test_service_account_and_share_controls(self):
        data = fixture("hardened")
        data["service_accounts"].append(
            {"name": "disabled", "enabled": False, "password_never_expires": True, "managed": False})
        data["shares"][0]["access"].append(
            {"principal_sid": "S-1-1-0", "type": "Allow", "right": "Read"})
        self.assertTrue(all(row["status"] == "pass" for row in audit(data).values()))
