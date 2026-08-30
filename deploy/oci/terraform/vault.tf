resource "oci_kms_vault" "clixor" {
  compartment_id = local.deployment_compartment_id
  display_name   = "clixor-prod-vault"
  vault_type     = "DEFAULT"
  freeform_tags  = local.tags
}
resource "oci_kms_key" "runtime_secrets" {
  compartment_id      = local.deployment_compartment_id
  display_name        = "clixor-prod-runtime-secrets"
  management_endpoint = oci_kms_vault.clixor.management_endpoint
  protection_mode     = "SOFTWARE"

  key_shape {
    algorithm = "AES"
    length    = 32
  }

  freeform_tags = local.tags
}
