package common

import rego.v1

# Operates on `terraform show -json <plan>` output, not raw HCL. That
# matters here: a scanner reading raw HCL (tfsec/Trivy's default GCP IAM
# checks) cannot resolve member = "serviceAccount:${google_service_account.x.email}"
# since that's a cross-resource reference, so it silently misses a
# roles/owner grant written the idiomatic way instead of as a hardcoded
# string. Terraform's own plan JSON resolves it, because the provider
# computes the email deterministically from account_id + project with no
# API call needed. walk() recurses through root_module and every nested
# child_module so this finds resources regardless of module depth.
all_planned_resources contains r if {
	walk(input.planned_values.root_module, [_, value])
	is_object(value)
	value.address
	value.type
	value.values
	r := value
}
