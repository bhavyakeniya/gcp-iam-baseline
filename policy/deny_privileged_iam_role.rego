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
