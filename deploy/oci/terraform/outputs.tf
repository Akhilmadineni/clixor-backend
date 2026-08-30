output "deployment_compartment_id" {
  description = "Compartment containing Clixor resources."
  value       = local.deployment_compartment_id
}

output "availability_domain" {
  description = "Availability domain selected for the A1 instance and data volume."
  value       = local.availability_domain
}

output "ubuntu_image_id" {
  description = "Source-controlled Canonical Ubuntu 24.04 ARM64 image OCID."
  value       = local.ubuntu_image_id
}

output "instance_id" {
  description = "Clixor production instance OCID."
  value       = oci_core_instance.clixor.id
}

output "instance_private_ip" {
  description = "Private IP used when creating an OCI Bastion session."
  value       = oci_core_instance.clixor.private_ip
}

output "bastion_id" {
  description = "OCI Bastion OCID."
  value       = oci_bastion_bastion.clixor.id
}

output "bastion_private_endpoint_ip" {
  description = "Private endpoint used by Bastion inside the application subnet."
  value       = oci_bastion_bastion.clixor.private_endpoint_ip_address
}

output "backup_bucket_name" {
  description = "Private bucket receiving encrypted logical backups."
  value       = oci_objectstorage_bucket.backups.name
}

output "object_storage_namespace" {
  description = "Tenancy Object Storage namespace used by the native OCI media provider."
  value       = data.oci_objectstorage_namespace.tenancy.namespace
}

output "media_bucket_name" {
  description = "Private bucket used as the primary application-media store."
  value       = oci_objectstorage_bucket.media.name
}

output "media_bucket_id" {
  description = "OCID of the primary application-media bucket."
  value       = oci_objectstorage_bucket.media.bucket_id
}

output "object_storage_region" {
  description = "OCI region containing the media and backup buckets."
  value       = var.region
}

output "object_storage_native_endpoint" {
  description = "Namespace-specific native Object Storage endpoint used by OCI SDK calls and returned PAR URLs."
  value       = "https://${data.oci_objectstorage_namespace.tenancy.namespace}.objectstorage.${var.region}.oci.customer-oci.com"
}

output "vault_id" {
  description = "Default Vault OCID. Secret values must be added after apply, outside Terraform."
  value       = oci_kms_vault.clixor.id
}

output "vault_key_id" {
  description = "Software-protected Vault key OCID for separately created runtime secrets."
  value       = oci_kms_key.runtime_secrets.id
}

output "data_volume_id" {
  description = "Attached data-volume OCID mounted at /srv/clixor."
  value       = oci_core_volume.clixor_data.id
}

output "mail_dkim_cname_name" {
  description = "Public Cloudflare DNS CNAME name required for OCI DKIM."
  value       = oci_email_dkim.transactional_mail.dns_subdomain_name
}

output "mail_dkim_cname_value" {
  description = "Public Cloudflare DNS CNAME target required for OCI DKIM."
  value       = oci_email_dkim.transactional_mail.cname_record_value
}

output "mail_spf_txt_name" {
  description = "Public Cloudflare DNS TXT name required for the Phoenix sending domain SPF policy."
  value       = local.mail_domain
}

output "mail_spf_txt_value" {
  description = "Public Cloudflare DNS TXT value required for the Phoenix sending domain SPF policy."
  value       = local.mail_spf_txt_value
}

output "mail_smtp_endpoint" {
  description = "OCI Email Delivery implicit-TLS submission endpoint and port."
  value       = local.mail_smtp_endpoint
}

output "mail_smtp_user_id" {
  description = "Dedicated IAM user OCID on which an operator manually issues the SMTP credential after apply."
  value       = oci_identity_user.smtp_submitter.id
}
