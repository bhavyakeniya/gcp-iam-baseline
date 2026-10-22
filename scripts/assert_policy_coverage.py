#!/usr/bin/env python3
"""Assert exact OPA rule coverage against a Terraform plan, not just a
non-zero exit code. A plain `if conftest test ...; then exit 1; fi` treats
ANY failure - a crash, a typo'd policy path, one rule firing while a
sibling rule silently regressed - as "the known-bad plan correctly
failed". This asserts each --expect-rule namespace actually reported a
violation on the fail plan, and that the pass plan has zero violations
anywhere.
"""
import argparse
import json
import subprocess
import sys


def run_conftest(plan_path, policy_dir):
    result = subprocess.run(
        ["conftest", "test", "--all-namespaces", plan_path, "--policy", policy_dir, "-o", "json"],
        capture_output=True,
        text=True,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"conftest produced non-JSON output for {plan_path}:\n{result.stdout}\n{result.stderr}", file=sys.stderr)
        sys.exit(1)


def failing_namespaces(report):
    return {entry["namespace"] for entry in report if entry.get("failures")}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fail-plan", required=True)
    parser.add_argument("--pass-plan", required=True)
    parser.add_argument("--policy-dir", required=True)
    parser.add_argument("--expect-rule", action="append", required=True, dest="expect_rules")
    args = parser.parse_args()

    ok = True

    fail_report = run_conftest(args.fail_plan, args.policy_dir)
    fail_namespaces = failing_namespaces(fail_report)
    for rule in args.expect_rules:
        if rule not in fail_namespaces:
            print(f"FAIL: expected rule {rule!r} to report a violation on {args.fail_plan}, but it did not. "
                  f"Namespaces that did report violations: {sorted(fail_namespaces)}", file=sys.stderr)
            ok = False
    if ok:
        print(f"OK: all {len(args.expect_rules)} expected rules reported a violation on {args.fail_plan}")

    pass_report = run_conftest(args.pass_plan, args.policy_dir)
    pass_namespaces = failing_namespaces(pass_report)
    if pass_namespaces:
        print(f"FAIL: {args.pass_plan} should have zero violations, but these rules reported some: "
              f"{sorted(pass_namespaces)}", file=sys.stderr)
        ok = False
    else:
        print(f"OK: {args.pass_plan} reported zero violations")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
