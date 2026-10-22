output "service_account_email" {
  description = "Email of the created service account."
  value       = google_service_account.this.email
}

output "service_account_id" {
  description = "Fully-qualified resource ID of the created service account."
  value       = google_service_account.this.id
}

output "custom_role_id" {
  description = "Fully-qualified ID of the custom role granting this service account its permissions."
  value       = google_project_iam_custom_role.this.id
}
