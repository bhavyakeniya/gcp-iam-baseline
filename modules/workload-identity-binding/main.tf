terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0"
    }
  }
}

# Binds a Kubernetes ServiceAccount to a GCP service account via GKE
# Workload Identity Federation. There is no google_service_account_key
# resource anywhere in this module - that is deliberate. Workload Identity
# removes the need for a long-lived key entirely, and this module does not
# expose a way to create one.
resource "google_service_account_iam_member" "workload_identity" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/${var.service_account_email}"
  role                = "roles/iam.workloadIdentityUser"
  member              = "serviceAccount:${var.project_id}.svc.id.goog[${var.k8s_namespace}/${var.k8s_service_account_name}]"
}
