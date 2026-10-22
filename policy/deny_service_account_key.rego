package policies.service_account_key

import data.common

# No built-in tfsec/Trivy rule blocks google_service_account_key outright -
# the resource type itself is the violation, regardless of which service
# account it attaches to or what the key is used for.

deny contains msg if {
	rc := common.all_planned_resources[_]
	rc.type == "google_service_account_key"
	msg := sprintf("%s creates a static GCP service-account key; use Workload Identity Federation instead", [rc.address])
}
