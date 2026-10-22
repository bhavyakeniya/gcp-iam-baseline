terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0"
    }
  }
}

variable "project_id" {
  type    = string
  default = "example-project"
}

module "app_identity" {
  source = "../../modules/least-privilege-service-account"

  project_id   = var.project_id
  account_id   = "app-sa"
  display_name = "App service account"
  role_id      = "appServiceAccountRole"
  permissions = [
    "storage.objects.get",
    "storage.objects.list",
  ]
}

module "app_workload_identity" {
  source = "../../modules/workload-identity-binding"

  project_id               = var.project_id
  service_account_email    = module.app_identity.service_account_email
  k8s_namespace            = "data-platform"
  k8s_service_account_name = "app-sa"
}

output "kubernetes_service_account_annotation" {
  value = module.app_workload_identity.kubernetes_service_account_annotation
}
