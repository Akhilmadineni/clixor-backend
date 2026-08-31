locals {
  mail_domain        = "mail.atlanteanz.com"
  mail_sender        = "no-reply@${local.mail_domain}"
  mail_dkim_selector = "clixor-phx-20260830"
  mail_spf_txt_value = "v=spf1 include:rp.oracleemaildelivery.com ~all"
  mail_smtp_endpoint = "smtp.email.${var.region}.oci.oraclecloud.com:465"
}

resource "oci_email_email_domain" "transactional_mail" {
  compartment_id = local.deployment_compartment_id
  name           = local.mail_domain
  description    = "Clixor transactional password-reset mail domain"
  freeform_tags  = local.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_email_dkim" "transactional_mail" {
  email_domain_id = oci_email_email_domain.transactional_mail.id
  name            = local.mail_dkim_selector
  description     = "OCI-generated DKIM signing key for Clixor transactional mail"
  freeform_tags   = local.tags

  # Deliberately omit private_key. OCI generates and retains the signing key;
  # Terraform stores only the public DNS record returned by Email Delivery.
  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_email_sender" "password_reset" {
  count = var.create_mail_approved_sender ? 1 : 0

  compartment_id = local.deployment_compartment_id
  email_address  = local.mail_sender
  freeform_tags  = local.tags

  depends_on = [oci_email_dkim.transactional_mail]

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = oci_email_dkim.transactional_mail.state == "ACTIVE"
      error_message = "Publish the Terraform-output DKIM CNAME in Cloudflare and wait for OCI DKIM state ACTIVE before enabling create_mail_approved_sender."
    }
  }
}

resource "oci_identity_user" "smtp_submitter" {
  # The production SMTP principal predates Resource Manager state. Keep it
  # external by default so routine infrastructure updates cannot recreate it.
  # Adopt it with `terraform import` before deliberately enabling management.
  count = var.manage_smtp_submitter_identity ? 1 : 0

  compartment_id = var.tenancy_ocid
  name           = "clixor-email-smtp"
  description    = "Non-interactive IAM user for Clixor OCI Email Delivery SMTP submission"
  freeform_tags  = local.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_identity_user_capabilities_management" "smtp_submitter" {
  count   = var.manage_smtp_submitter_identity ? 1 : 0
  user_id = oci_identity_user.smtp_submitter[0].id

  can_use_api_keys             = false
  can_use_auth_tokens          = false
  can_use_console_password     = false
  can_use_customer_secret_keys = false
  can_use_smtp_credentials     = true
}

resource "oci_identity_group" "smtp_submitters" {
  compartment_id = var.tenancy_ocid
  name           = "ClixorEmailSmtpSubmitters"
  description    = "Dedicated group permitted only to submit Clixor mail through OCI Email Delivery"
  freeform_tags  = local.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_identity_user_group_membership" "smtp_submitter" {
  count    = var.manage_smtp_submitter_identity ? 1 : 0
  group_id = oci_identity_group.smtp_submitters.id
  user_id  = oci_identity_user.smtp_submitter[0].id
}

resource "oci_identity_policy" "smtp_submission" {
  compartment_id = var.tenancy_ocid
  name           = "ClixorEmailSmtpSubmission"
  description    = "Compartment-scoped SMTP submission permission for the dedicated Clixor user"

  statements = [
    "Allow group ${oci_identity_group.smtp_submitters.name} to use approved-senders in compartment id ${local.deployment_compartment_id} where target.approved-sender.emailaddress = '${local.mail_sender}'",
  ]

  freeform_tags = local.tags
}
