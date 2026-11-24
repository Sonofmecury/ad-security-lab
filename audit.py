"""Compare evidence from two deliberately narrow AD configuration snapshots."""
import argparse
import json
from pathlib import Path


def privileged_members(data):
    return {str(member).casefold() for member in data["domain_admins"]}


def audit(data):
    findings = {}
    for key, test in {
        "AD-001": lambda: privileged_members(data) - {
            str(member).casefold() for member in data["approved_domain_admins"]
        },
        "AD-002": lambda: {item["name"] for item in data["service_accounts"]
                           if item["enabled"] and item["password_never_expires"]
                           and not item["managed"]},
        "AD-003": lambda: {item["name"] for item in data["shares"]
                           if any(ace["principal_sid"] in {"S-1-1-0", "S-1-5-11"}
                                  and ace["type"] == "Allow"
                                  and ace["right"] in {"Full", "Change"}
                                  for ace in item["access"])},
    }.items():
        try:
            evidence = sorted(test())
            findings[key] = {"status": "fail" if evidence else "pass", "evidence": evidence}
        except (KeyError, TypeError, ValueError) as error:
            findings[key] = {"status": "unknown", "evidence": [f"Incomplete snapshot: {error}"]}
    return findings


def compare(before, after):
    start, end = audit(before), audit(after)
    return {key: {"before": start[key], "after": end[key],
                  "verified_closed": start[key]["status"] == "fail"
                  and end[key]["status"] == "pass"}
            for key in start}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("after", type=Path, nargs="?")
    args = parser.parse_args()
    before = json.loads(args.baseline.read_text(encoding="utf-8-sig"))
    result = compare(before, json.loads(args.after.read_text(encoding="utf-8-sig"))) if args.after else audit(before)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
