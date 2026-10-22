package policies.privileged_iam_role

test_owner_role_denied if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_member.bad",
		"type": "google_project_iam_member",
		"values": {"role": "roles/owner", "member": "serviceAccount:bad@x.iam.gserviceaccount.com"},
	}]}}}
	count(deny) > 0 with input as mock_input
}

test_editor_role_denied if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_member.bad",
		"type": "google_project_iam_member",
		"values": {"role": "roles/editor", "member": "serviceAccount:bad@x.iam.gserviceaccount.com"},
	}]}}}
	count(deny) > 0 with input as mock_input
}

test_custom_role_allowed if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_member.good",
		"type": "google_project_iam_member",
		"values": {"role": "projects/x/roles/appServiceAccountRole", "member": "serviceAccount:good@x.iam.gserviceaccount.com"},
	}]}}}
	count(deny) == 0 with input as mock_input
}

test_owner_role_in_nested_module_denied if {
	mock_input := {"planned_values": {"root_module": {
		"resources": [],
		"child_modules": [{
			"address": "module.app",
			"resources": [{
				"address": "module.app.google_project_iam_member.bad",
				"type": "google_project_iam_member",
				"values": {"role": "roles/owner", "member": "serviceAccount:bad@x.iam.gserviceaccount.com"},
			}],
		}],
	}}}
	count(deny) > 0 with input as mock_input
}

test_authoritative_policy_with_owner_denied if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_policy.bad",
		"type": "google_project_iam_policy",
		"values": {"policy_data": "{\"bindings\":[{\"role\":\"roles/owner\",\"members\":[\"serviceAccount:bad@x.iam.gserviceaccount.com\"]}]}"},
	}]}}}
	count(deny) > 0 with input as mock_input
}

test_authoritative_policy_without_privileged_role_allowed if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_policy.good",
		"type": "google_project_iam_policy",
		"values": {"policy_data": "{\"bindings\":[{\"role\":\"projects/x/roles/appServiceAccountRole\",\"members\":[\"serviceAccount:good@x.iam.gserviceaccount.com\"]}]}"},
	}]}}}
	count(deny) == 0 with input as mock_input
}
