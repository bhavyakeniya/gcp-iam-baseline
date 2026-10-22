package policies.privileged_iam_role

import data.common

privileged_roles := {"roles/owner", "roles/editor"}

iam_binding_types := {
	"google_project_iam_member",
	"google_project_iam_binding",
	"google_folder_iam_member",
	"google_folder_iam_binding",
	"google_organization_iam_member",
	"google_organization_iam_binding",
}

deny contains msg if {
	rc := common.all_planned_resources[_]
	rc.type in iam_binding_types
	rc.values.role in privileged_roles
	msg := sprintf("%s grants privileged role %q; grant a custom role scoped to only the permissions actually needed", [rc.address, rc.values.role])
}

authoritative_iam_policy_types := {
	"google_project_iam_policy",
	"google_folder_iam_policy",
	"google_organization_iam_policy",
}

# google_project_iam_policy (and its folder/org equivalents) sets the
# *entire* IAM policy authoritatively, overwriting any binding not listed -
# this is why Google's own provider docs recommend _iam_member/_iam_binding
# instead. Its role grants live inside a JSON-encoded policy_data string
# rather than a flat `role` attribute, so it needs its own decode step.
deny contains msg if {
	rc := common.all_planned_resources[_]
	rc.type in authoritative_iam_policy_types
	policy := json.unmarshal(rc.values.policy_data)
	binding := policy.bindings[_]
	binding.role in privileged_roles
	msg := sprintf("%s sets an authoritative IAM policy granting privileged role %q via policy_data; use additive google_project_iam_member/_binding with a custom role instead", [rc.address, binding.role])
}
