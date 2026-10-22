package policies.public_iam_principal

import data.common

# Granting ANY role, including roles/viewer, to allUsers or
# allAuthenticatedUsers exposes project/folder/org resources to the public
# internet or every Google account on earth. This is independent of which
# role is granted - deny_privileged_iam_role only checks the role name, so
# a public grant of a low-privilege-sounding role like roles/viewer slips
# past it entirely. Verified directly: roles/viewer granted to allUsers
# produced zero violations before this policy existed.
#
# Scope: project/folder/organization-level IAM only. Resource-level public
# grants (e.g. google_storage_bucket_iam_member to allUsers) are out of
# scope here on purpose - tfsec's google-storage-no-public-access check
# already catches that case (verified: it fires on examples/fail today).
# Duplicating it here would just be two checks disagreeing about the same
# resource type for no benefit.

public_principals := {"allUsers", "allAuthenticatedUsers"}

# object.get with a fallback matters here, not just for tidiness: an
# earlier version built the message with rc.values.role directly, and
# since sprintf can't resolve an undefined argument, that made the entire
# rule undefined whenever role was missing - silently skipping a resource
# that WAS granted to a public principal, just because the role couldn't be
# printed. Verified directly: a resource with member=allUsers and no role
# attribute produced zero violations under the old code. Detection must
# never depend on a value that's only needed for display.
role_or_unknown(values) := object.get(values, "role", "<unknown>")

member_binding_types := {
	"google_project_iam_member",
	"google_folder_iam_member",
	"google_organization_iam_member",
}

deny contains msg if {
	rc := common.all_planned_resources[_]
	rc.type in member_binding_types
	rc.values.member in public_principals
	msg := sprintf("%s grants role %q to public principal %q", [rc.address, role_or_unknown(rc.values), rc.values.member])
}

binding_types := {
	"google_project_iam_binding",
	"google_folder_iam_binding",
	"google_organization_iam_binding",
}

deny contains msg if {
	rc := common.all_planned_resources[_]
	rc.type in binding_types
	member := rc.values.members[_]
	member in public_principals
	msg := sprintf("%s grants role %q to public principal %q", [rc.address, role_or_unknown(rc.values), member])
}

authoritative_iam_policy_types := {
	"google_project_iam_policy",
	"google_folder_iam_policy",
	"google_organization_iam_policy",
}

deny contains msg if {
	rc := common.all_planned_resources[_]
	rc.type in authoritative_iam_policy_types
	policy := json.unmarshal(rc.values.policy_data)
	binding := policy.bindings[_]
	member := binding.members[_]
	member in public_principals
	msg := sprintf("%s sets an authoritative IAM policy granting role %q to public principal %q via policy_data", [rc.address, role_or_unknown(binding), member])
}
