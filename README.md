# gcp-iam-baseline

Reusable Terraform modules for a least-privilege, static-key-free GCP IAM baseline,
backed by two layers of policy-as-code CI gating: [tfsec](https://github.com/aquasecurity/tfsec)
for general misconfiguration scanning, and a small set of custom [OPA](https://www.openpolicyagent.org/)/Rego
checks run against `terraform show -json` plan output for the IAM-specific gaps tfsec's
default ruleset doesn't catch.

This is a from-scratch demo repo, not a copy of any employer's codebase. It
reimplements, generically and with synthetic examples, the same IAM hardening
pattern (Workload Identity over static keys, custom roles over primitive roles,
CI-gated IaC security scanning) used in real platform-engineering work I've shipped.

## Modules

| Module | What it does |
|---|---|
| `modules/least-privilege-service-account` | Creates a service account bound to a **custom role** built from an explicit permission list. There is no `role` input that accepts a primitive role (`roles/owner`, `roles/editor`) - the module's interface makes that class of mistake impossible, not just discouraged. |
| `modules/workload-identity-binding` | Binds a Kubernetes ServiceAccount to a GCP service account via GKE Workload Identity Federation (`roles/iam.workloadIdentityUser`). There is no `google_service_account_key` resource anywhere in this module; it has no code path that can create a static key. Outputs the exact `iam.gke.io/gcp-service-account` annotation value to put on the Kubernetes ServiceAccount - the same annotation enforced by the `deny_static_gcp_key` policy in [k8s-policy-guardrails](https://github.com/bhavyakeniya/k8s-policy-guardrails). |

`examples/pass/` wires both modules together into a realistic usage example.
`examples/fail/` is a deliberately insecure, hand-written Terraform file (not using
the modules) that creates a static service-account key, grants `roles/owner`, grants
`roles/viewer` to `allUsers`, and defines a custom role containing
`resourcemanager.projects.setIamPolicy` - one resource per policy in this repo, all in
one plan, so CI can assert each policy fires independently rather than just checking
that *something* failed.

## Why two scanning layers instead of one

I initially wired up tfsec alone, pointed it at `examples/fail/`, and expected it to
flag the static key and the `roles/owner` grant. It didn't - it only caught the
storage-bucket findings. Digging into why surfaced a real, worth-knowing limitation:

tfsec and Trivy's default GCP IAM checks (`google-iam-no-privileged-service-accounts`,
etc.) work against the raw Terraform HCL. When a `member` value is a literal string,
they resolve it fine. When it's built from a cross-resource reference -
`member = "serviceAccount:${google_service_account.legacy.email}"`, the idiomatic way
to write it - the static HCL analyzer can't compute the referenced attribute and the
finding silently disappears. No error, no warning, just a missed finding. I confirmed
this with a minimal reproduction (see commit history): the identical policy with a
hardcoded member string gets caught; the version referencing the service account
resource does not.

That means realistic Terraform - the kind that references the resource it just
created instead of hardcoding a string - is *more* likely to slip past these two
scanners than lazily-written code. Terraform's own `terraform show -json` plan
output doesn't have this gap: the provider computes `google_service_account.email`
deterministically from `account_id` + `project`, so the plan JSON resolves it even
without any API calls. The `policy/` directory here runs four small OPA checks against
that plan JSON instead:

| Policy | Catches |
|---|---|
| `policy/deny_service_account_key.rego` | Any `google_service_account_key` resource, anywhere in the plan (root or nested module) |
| `policy/deny_privileged_iam_role.rego` | `roles/owner`/`roles/editor` granted via `google_project_iam_member`/`_binding` (or folder/org equivalent), **and** via the authoritative `google_project_iam_policy`/`_folder_/_organization_` resources, whose role grants live inside a JSON-encoded `policy_data` string rather than a flat `role` attribute |
| `policy/deny_public_iam_principal.rego` | Any role at all - including low-privilege-sounding ones like `roles/viewer` - granted to `allUsers`/`allAuthenticatedUsers`. The privileged-role check only looks at the role name, so a public grant of a "safe" role slipped past it entirely until this policy existed. |
| `policy/deny_dangerous_custom_role_permissions.rego` | A **custom** role (the thing `least-privilege-service-account` builds) that itself contains a privilege-escalation permission - `resourcemanager.*.setIamPolicy`, `iam.serviceAccounts.actAs`/`getAccessToken`/`signJwt`/`signBlob`/`setIamPolicy`, `iam.serviceAccountKeys.create`. A custom role is not automatically safe just because it isn't `roles/owner`. |

Both of the above came out of an adversarial pass after the first external review: I fed the policies a custom role containing only `resourcemanager.projects.setIamPolicy` and a `roles/viewer` grant to `allUsers`, and both passed clean. Fixed and covered by tests now - see commit history rather than trusting this README alone.

`terraform plan` needs a GCP credential to even start, including in CI where nothing
real should ever be configured. `.github/workflows/ci.yml` generates a throwaway RSA
key and a syntactically-valid-but-fake service-account JSON at runtime (never
committed, so there's nothing for a secret scanner to flag) purely so the provider
can produce a plan for brand-new resources with no API calls involved.

tfsec stays in CI for what it's actually good at - bucket exposure, encryption,
network configuration - and the OPA layer covers the IAM-specific gaps it misses for
this resource-reference pattern, plus checks (public principals, dangerous custom-role
permissions) that are entirely outside tfsec's scope regardless of the reference issue.

## Prerequisites

```bash
brew install opa conftest tfsec terraform
```

## Usage

```bash
# Unit test the OPA policies
opa test policy/ -v

# tfsec against the modules or a config directory
tfsec modules

# The plan-based OPA check (what CI actually runs)
cd examples/fail   # or examples/pass
terraform init -backend=false
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
conftest test --all-namespaces tfplan.json --policy ../../policy
```

## Project structure

```
modules/
  least-privilege-service-account/   # custom-role-only service account
  workload-identity-binding/         # Workload Identity binding, no key resource
policy/
  common.rego                           # package common - walk()'s the plan tree for every resource
  deny_service_account_key.rego         # package policies.service_account_key
  deny_privileged_iam_role.rego         # package policies.privileged_iam_role
  deny_public_iam_principal.rego        # package policies.public_iam_principal
  deny_dangerous_custom_role_permissions.rego  # package policies.dangerous_custom_role_permissions
  *_test.rego                           # opa test unit tests, mocked plan JSON
examples/
  pass/                               # uses both modules; must pass tfsec and every OPA policy
  fail/                               # one resource per policy; each must fail independently
scripts/assert_policy_coverage.py     # asserts exact rule coverage, not just a non-zero exit
.github/workflows/ci.yml              # terraform validate, opa test, tfsec, plan-based OPA check
```

## CI

`.github/workflows/ci.yml` installs checksum-verified OPA, conftest, and tfsec
binaries and SHA-pinned actions (plus HashiCorp's official `setup-terraform` action),
runs with `permissions: contents: read`, checks `terraform fmt`, validates every
module and example, runs the OPA unit tests, runs tfsec against the known-good
example and the modules, asserts tfsec *does* flag the known-bad example (the bucket
findings this README talks about above), then generates a real Terraform plan for
both examples and runs `scripts/assert_policy_coverage.py` against them.

That script exists because `if conftest test ...; then exit 1; fi` only proves *some*
rule fired - a silent regression in one policy can hide behind a sibling policy still
firing on the same combined fixture, and the script would have let it. It instead
parses conftest's structured JSON output and asserts each of the four policy packages
by name reported a violation on the known-bad plan, and that the known-good plan has
zero violations from any package.

`.terraform.lock.hcl` is committed for `examples/pass` and `examples/fail` (they're
root configurations - HashiCorp's own guidance is to commit lockfiles there) and
gitignored inside each module directory (reusable child modules don't need their own).

## Scope and known limitations

This repo enforces its rules at the Terraform-plan layer. It does not stop someone
from creating a static key or an overly broad grant through `gcloud`, the GCP
console, or a different repository's Terraform - that needs an org-level control
(a GCP Organization Policy constraint restricting service-account key creation, for
example), which this repo doesn't currently define. An earlier version of this
section claimed that was untestable offline; that was wrong and got corrected after
a review pointed it out - Terraform's own `mock_provider` test framework (stable
since Terraform 1.6+, this repo already requires >= 1.8.0) can exercise an
org-policy resource's planned configuration with no real GCP org or credentials,
the same way everything else in this repo is tested. What genuinely can't be tested
offline is whether a *real* org actually enforces the constraint - the Terraform
code itself could be. Not yet built here; worth knowing before treating this repo as
a complete guardrail rather than a CI-time gate.
