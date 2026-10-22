package policies.dangerous_custom_role_permissions

import data.common

# The least-privilege-service-account module's entire pitch is that a
# custom role built from an explicit permission list can't accidentally
# become roles/owner. That is true for the *role name*, but a "custom"
# role is not automatically safe - a caller can still list a permission
# that itself grants privilege escalation (rewriting IAM policy, minting
# service-account keys or tokens for another identity). Verified directly:
# a custom role with only resourcemanager.projects.setIamPolicy produced
# zero violations before this policy existed.
#
# This is a curated, explicitly non-exhaustive denylist of permissions that
# grant IAM/org-policy control or service-account impersonation - not a
# generated list from GCP's full permission reference. Known gaps include
# iam.serviceAccounts.getOpenIdToken/implicitDelegation,
# iam.serviceAccountKeys.upload, iam.roles.create/update,
# orgpolicy.policy.set, and cloudbuild.builds.create (a build can itself run
# as a highly-privileged service account). Expanding this against a
# documented threat model is a reasonable next step; until then, treat a
# clean result from this policy as "no permission on this specific list",
# not "no privilege-escalation risk".
dangerous_permissions := {
	"resourcemanager.projects.setIamPolicy",
	"resourcemanager.folders.setIamPolicy",
	"resourcemanager.organizations.setIamPolicy",
	"iam.serviceAccounts.setIamPolicy",
	"iam.serviceAccounts.actAs",
	"iam.serviceAccounts.getAccessToken",
	"iam.serviceAccounts.getOpenIdToken",
	"iam.serviceAccounts.implicitDelegation",
	"iam.serviceAccounts.signJwt",
	"iam.serviceAccounts.signBlob",
	"iam.serviceAccountKeys.create",
	"iam.serviceAccountKeys.upload",
	"iam.roles.create",
	"iam.roles.update",
	"orgpolicy.policy.set",
	"cloudbuild.builds.create",
}

custom_role_types := {
	"google_project_iam_custom_role",
	"google_organization_iam_custom_role",
}

deny contains msg if {
	rc := common.all_planned_resources[_]
	rc.type in custom_role_types
	permission := rc.values.permissions[_]
	permission in dangerous_permissions
	msg := sprintf("%s grants permission %q, which allows privilege escalation (IAM policy edits, service-account impersonation/keys) regardless of the custom role's name", [rc.address, permission])
}
