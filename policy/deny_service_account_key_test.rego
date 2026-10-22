package policies.service_account_key

test_service_account_key_denied if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_service_account_key.legacy_key",
		"type": "google_service_account_key",
		"values": {},
	}]}}}
	count(deny) > 0 with input as mock_input
}

test_service_account_key_in_nested_module_denied if {
	mock_input := {"planned_values": {"root_module": {
		"resources": [],
		"child_modules": [{
			"address": "module.app",
			"resources": [{
				"address": "module.app.google_service_account_key.k",
				"type": "google_service_account_key",
				"values": {},
			}],
		}],
	}}}
	count(deny) > 0 with input as mock_input
}

test_no_service_account_key_allowed if {
	mock_input := {"planned_values": {"root_module": {"resources": [{
		"address": "google_service_account.app",
		"type": "google_service_account",
		"values": {},
	}]}}}
	count(deny) == 0 with input as mock_input
}
