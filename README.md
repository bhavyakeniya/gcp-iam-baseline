# gcp-iam-baseline

Reusable Terraform modules for a least-privilege, static-key-free GCP IAM baseline,
backed by two layers of policy-as-code CI gating: [tfsec](https://github.com/aquasecurity/tfsec)
for general misconfiguration scanning, and a small set of custom [OPA](https://www.openpolicyagent.org/)/Rego
checks run against `terraform show -json` plan output for the two things tfsec's
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
the modules) that creates a static service-account key and grants `roles/owner`
directly, so CI has something real to catch.

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
without any API calls. The `policy/` directory here runs two small OPA checks against
that plan JSON instead:

| Policy | Catches |
|---|---|
| `policy/deny_service_account_key.rego` | Any `google_service_account_key` resource, anywhere in the plan (root or nested module) |
| `policy/deny_privileged_iam_role.rego` | `roles/owner`/`roles/editor` granted via `google_project_iam_member`/`_binding` (or folder/org equivalent), **and** via the authoritative `google_project_iam_policy`/`_folder_/_organization_` resources, whose role grants live inside a JSON-encoded `policy_data` string rather than a flat `role` attribute |

`terraform plan` needs a GCP credential to even start, including in CI where nothing
real should ever be configured. `.github/workflows/ci.yml` generates a throwaway RSA
key and a syntactically-valid-but-fake service-account JSON at runtime (never
committed, so there's nothing for a secret scanner to flag) purely so the provider
can produce a plan for brand-new resources with no API calls involved.

tfsec stays in CI for what it's actually good at - bucket exposure, encryption,
network configuration - and the OPA layer covers the two IAM-specific gaps it misses
for this resource-reference pattern.

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
  common.rego                        # package common - walk()'s the plan tree for every resource
  deny_service_account_key.rego      # package policies.service_account_key
  deny_privileged_iam_role.rego      # package policies.privileged_iam_role
  *_test.rego                        # opa test unit tests, mocked plan JSON
examples/
  pass/                               # uses both modules; must pass tfsec and the OPA check
  fail/                               # static key + roles/owner; must fail the OPA check
.github/workflows/ci.yml              # terraform validate, opa test, tfsec, plan-based OPA check
```

## CI

`.github/workflows/ci.yml` installs pinned OPA, conftest, and tfsec binaries (plus
HashiCorp's official `setup-terraform` action), validates every module and example,
runs the OPA unit tests, runs tfsec against the known-good example and the modules,
then generates a real Terraform plan for both examples and asserts the known-bad plan
fails the OPA check while the known-good plan passes it.
