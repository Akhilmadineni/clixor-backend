resource "oci_kms_vault" "clixor" {
  compartment_id = local.deployment_compartment_id
  display_name   = "clixor-prod-vault"
  vault_type     = "DEFAULT"
  freeform_tags  = local.tags
}

# OCI can report a new Vault as ACTIVE before its unique management hostname is
# resolvable from Resource Manager. Delay the first key request so a clean stack
# apply does not fail on that short control-plane DNS propagation window.
resource "time_sleep" "vault_management_dns" {
  depends_on      = [oci_kms_vault.clixor]
  create_duration = "90s"
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

  depends_on = [time_sleep.vault_management_dns]
}
