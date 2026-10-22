package policies.dangerous_custom_role_permissions

test_set_iam_policy_permission_denied if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_custom_role.escalator",
		"type": "google_project_iam_custom_role",
		"values": {"permissions": ["resourcemanager.projects.setIamPolicy"]},
	}]}}}
	count(deny) > 0 with input as mock_input
}

test_service_account_key_create_permission_denied if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_custom_role.keymaker",
		"type": "google_project_iam_custom_role",
		"values": {"permissions": ["iam.serviceAccountKeys.create"]},
	}]}}}
	count(deny) > 0 with input as mock_input
}

test_benign_permissions_allowed if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_custom_role.reader",
		"type": "google_project_iam_custom_role",
		"values": {"permissions": ["storage.objects.get", "storage.objects.list"]},
	}]}}}
	count(deny) == 0 with input as mock_input
}
