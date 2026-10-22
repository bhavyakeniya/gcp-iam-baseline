#!/usr/bin/env python3
"""Assert exact OPA rule coverage against a Terraform plan, not just a
non-zero exit code. A plain `if conftest test ...; then exit 1; fi` treats
ANY failure - a crash, a typo'd policy path, one rule firing while a
sibling rule silently regressed - as "the known-bad plan correctly
failed". This asserts each --expect-rule namespace actually reported a
violation on the fail plan, and that the pass plan has zero violations
anywhere.

It also doesn't stop at parsing stdout as JSON: a conftest process that
crashed partway could still flush a truncated-but-valid-looking JSON
array that's silently missing a package, which would look identical to
"that policy just didn't fire" from the JSON alone. So this checks the
process exit code against what each plan should produce (1 for the known-
bad plan, 0 for the known-good one) and checks every report entry for an
"exceptions" key, which conftest sets when a policy couldn't be evaluated
at all rather than evaluating cleanly to no result.
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
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"conftest produced non-JSON output for {plan_path} (exit {result.returncode}):\n"
              f"{result.stdout}\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return report, result.returncode


def failing_namespaces(report):
    return {entry["namespace"] for entry in report if entry.get("failures")}


def exceptions_in(report):
    return [(entry["namespace"], entry["exceptions"]) for entry in report if entry.get("exceptions")]


def check_no_exceptions(report, plan_path):
    excs = exceptions_in(report)
    if excs:
        print(f"FAIL: {plan_path} had policy evaluation exceptions, not just pass/fail results - "
              f"results are incomplete and cannot be trusted: {excs}", file=sys.stderr)
        return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fail-plan", required=True)
    parser.add_argument("--pass-plan", required=True)
    parser.add_argument("--policy-dir", required=True)
    parser.add_argument("--expect-rule", action="append", required=True, dest="expect_rules")
    args = parser.parse_args()

    ok = True

    fail_report, fail_rc = run_conftest(args.fail_plan, args.policy_dir)
    ok &= check_no_exceptions(fail_report, args.fail_plan)
    if fail_rc != 1:
        print(f"FAIL: conftest exited {fail_rc} against {args.fail_plan}, expected exactly 1 "
              f"(a known-bad plan must fail; any other code - including 0 or a crash code - "
              f"means the result can't be trusted)", file=sys.stderr)
        ok = False

    fail_namespaces = failing_namespaces(fail_report)
    for rule in args.expect_rules:
        if rule not in fail_namespaces:
            print(f"FAIL: expected rule {rule!r} to report a violation on {args.fail_plan}, but it did not. "
                  f"Namespaces that did report violations: {sorted(fail_namespaces)}", file=sys.stderr)
            ok = False
    if fail_namespaces.issuperset(args.expect_rules) and fail_rc == 1:
        print(f"OK: all {len(args.expect_rules)} expected rules reported a violation on {args.fail_plan}, "
              f"exit code 1, no exceptions")

    pass_report, pass_rc = run_conftest(args.pass_plan, args.policy_dir)
    ok &= check_no_exceptions(pass_report, args.pass_plan)
    if pass_rc != 0:
        print(f"FAIL: conftest exited {pass_rc} against {args.pass_plan}, expected exactly 0", file=sys.stderr)
        ok = False

    pass_namespaces = failing_namespaces(pass_report)
    if pass_namespaces:
        print(f"FAIL: {args.pass_plan} should have zero violations, but these rules reported some: "
              f"{sorted(pass_namespaces)}", file=sys.stderr)
        ok = False
    elif pass_rc == 0:
        print(f"OK: {args.pass_plan} reported zero violations, exit code 0, no exceptions")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
