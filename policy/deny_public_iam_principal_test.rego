package policies.public_iam_principal

test_all_users_viewer_denied if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_member.public",
		"type": "google_project_iam_member",
		"values": {"role": "roles/viewer", "member": "allUsers"},
	}]}}}
	count(deny) > 0 with input as mock_input
}

test_all_authenticated_users_denied if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_member.public",
		"type": "google_project_iam_member",
		"values": {"role": "roles/viewer", "member": "allAuthenticatedUsers"},
	}]}}}
	count(deny) > 0 with input as mock_input
}

test_binding_with_public_member_in_list_denied if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_binding.public",
		"type": "google_project_iam_binding",
		"values": {"role": "roles/viewer", "members": ["serviceAccount:ok@x.iam.gserviceaccount.com", "allUsers"]},
	}]}}}
	count(deny) > 0 with input as mock_input
}

test_named_service_account_member_allowed if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_member.ok",
		"type": "google_project_iam_member",
		"values": {"role": "roles/viewer", "member": "serviceAccount:app@x.iam.gserviceaccount.com"},
	}]}}}
	count(deny) == 0 with input as mock_input
}

test_public_member_with_missing_role_still_denied if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_member.no_role_field",
		"type": "google_project_iam_member",
		"values": {"member": "allUsers"},
	}]}}}
	count(deny) > 0 with input as mock_input
}

test_authoritative_policy_with_public_member_denied if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_policy.authoritative_public",
		"type": "google_project_iam_policy",
		"values": {"policy_data": "{\"bindings\":[{\"role\":\"roles/viewer\",\"members\":[\"allUsers\"]}]}"},
	}]}}}
	count(deny) > 0 with input as mock_input
}

test_authoritative_policy_without_public_member_allowed if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_project_iam_policy.ok",
		"type": "google_project_iam_policy",
		"values": {"policy_data": "{\"bindings\":[{\"role\":\"roles/viewer\",\"members\":[\"serviceAccount:ok@x.iam.gserviceaccount.com\"]}]}"},
	}]}}}
	count(deny) == 0 with input as mock_input
}
