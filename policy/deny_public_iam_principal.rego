package policies.public_iam_principal

import data.common

# Granting ANY role, including roles/viewer, to allUsers or
# allAuthenticatedUsers exposes project resources to the public internet or
# every Google account on earth. This is independent of which role is
# granted - deny_privileged_iam_role only checks the role name, so a public
# grant of a low-privilege-sounding role like roles/viewer slips past it
# entirely. Verified directly: roles/viewer granted to allUsers produced
# zero violations before this policy existed.

public_principals := {"allUsers", "allAuthenticatedUsers"}

member_binding_types := {
	"google_project_iam_member",
	"google_folder_iam_member",
	"google_organization_iam_member",
}

deny contains msg if {
	rc := common.all_planned_resources[_]
	rc.type in member_binding_types
	rc.values.member in public_principals
	msg := sprintf("%s grants role %q to public principal %q", [rc.address, rc.values.role, rc.values.member])
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
	msg := sprintf("%s grants role %q to public principal %q", [rc.address, rc.values.role, member])
}
