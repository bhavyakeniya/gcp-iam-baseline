terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0"
    }
  }
}

resource "google_service_account" "this" {
  project      = var.project_id
  account_id   = var.account_id
  display_name = var.display_name
}

# GCP soft-deletes custom roles for a 7-day grace period: destroying and
# immediately recreating a role with the same role_id in that window fails
# (or requires an explicit undelete) rather than just working. Pick a new
# role_id, or wait out the grace period, if iterating on this in dev/test.
resource "google_project_iam_custom_role" "this" {
  project     = var.project_id
  role_id     = var.role_id
  title       = var.display_name
  permissions = var.permissions
}

resource "google_project_iam_member" "this" {
  project = var.project_id
  role    = google_project_iam_custom_role.this.id
  member  = "serviceAccount:${google_service_account.this.email}"
}
