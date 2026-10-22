terraform {
  required_version = ">= 1.8.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 8.0, < 9.0"
    }
  }
}

variable "project_id" {
  type    = string
  default = "example-project"
}

# Deliberately insecure, hand-written (not using the modules in this repo)
# to prove tfsec catches exactly the anti-patterns the modules avoid.

resource "google_service_account" "legacy" {
  project      = var.project_id
  account_id   = "legacy-sa"
  display_name = "Legacy service account"
}

resource "google_service_account_key" "legacy_key" {
  service_account_id = google_service_account.legacy.name
}

resource "google_project_iam_member" "legacy_owner" {
  project = var.project_id
  role    = "roles/owner"
  member  = "serviceAccount:${google_service_account.legacy.email}"
}

resource "google_storage_bucket" "public" {
  name     = "legacy-public-bucket-example"
  project  = var.project_id
  location = "EU"
}

resource "google_storage_bucket_iam_member" "public_access" {
  bucket = google_storage_bucket.public.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_project_iam_member" "public_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "allUsers"
}

resource "google_project_iam_custom_role" "escalation_role" {
  project     = var.project_id
  role_id     = "legacyEscalationRole"
  title       = "Legacy escalation role"
  permissions = ["resourcemanager.projects.setIamPolicy"]
}
