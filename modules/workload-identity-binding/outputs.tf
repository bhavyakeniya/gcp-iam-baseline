output "kubernetes_service_account_annotation" {
  description = <<-EOT
    The exact annotation to put on the Kubernetes ServiceAccount so GKE
    resolves Workload Identity. This is the same annotation key enforced by
    the deny_static_gcp_key policy in the k8s-policy-guardrails repo.
  EOT
  value = {
    "iam.gke.io/gcp-service-account" = var.service_account_email
  }
}
