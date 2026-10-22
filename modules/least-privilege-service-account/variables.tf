variable "project_id" {
  description = "GCP project the service account and custom role are created in."
  type        = string
}

variable "account_id" {
  description = "Service account ID (the part before @project.iam.gserviceaccount.com)."
  type        = string
}

variable "display_name" {
  description = "Human-readable name for the service account and custom role."
  type        = string
}

variable "role_id" {
  description = "ID for the custom IAM role created for this service account."
  type        = string
}

variable "permissions" {
  description = <<-EOT
    Exact IAM permissions to grant, e.g. ["storage.objects.get"]. There is
    deliberately no "role" input here: this module only ever grants a
    custom role built from this list, so a caller cannot accidentally wire
    up a primitive role like roles/owner or roles/editor through it.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.permissions) > 0
    error_message = "permissions must list at least one specific IAM permission."
  }
}
