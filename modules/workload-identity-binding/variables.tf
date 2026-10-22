variable "project_id" {
  description = "GCP project the GKE cluster and service account live in."
  type        = string
}

variable "service_account_email" {
  description = "Email of the GCP service account the Kubernetes service account should impersonate."
  type        = string
}

variable "k8s_namespace" {
  description = "Kubernetes namespace of the service account being bound."
  type        = string
}

variable "k8s_service_account_name" {
  description = "Name of the Kubernetes service account being bound."
  type        = string
}
