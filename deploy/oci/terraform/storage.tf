data "oci_objectstorage_namespace" "tenancy" {
  compartment_id = var.tenancy_ocid
}

resource "oci_objectstorage_bucket" "media" {
  compartment_id        = local.deployment_compartment_id
  namespace             = data.oci_objectstorage_namespace.tenancy.namespace
  name                  = var.media_bucket_name
  access_type           = "NoPublicAccess"
  auto_tiering          = "Disabled"
  object_events_enabled = false
  storage_tier          = "Standard"
  versioning            = "Disabled"
  freeform_tags         = local.tags

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = var.media_bucket_name != var.backup_bucket_name
      error_message = "media_bucket_name and backup_bucket_name must be different."
    }
  }
}

resource "oci_objectstorage_object_lifecycle_policy" "media" {
  namespace = data.oci_objectstorage_namespace.tenancy.namespace
  bucket    = oci_objectstorage_bucket.media.name

  rules {
    action      = "ABORT"
    is_enabled  = true
    name        = "abort-incomplete-multipart-uploads-after-1-day"
    target      = "multipart-uploads"
    time_amount = 1
    time_unit   = "DAYS"
  }

  depends_on = [oci_identity_policy.object_storage_lifecycle]
}

resource "oci_objectstorage_bucket" "backups" {
  compartment_id = local.deployment_compartment_id
  namespace      = data.oci_objectstorage_namespace.tenancy.namespace
  name           = var.backup_bucket_name
  access_type    = "NoPublicAccess"
  auto_tiering   = "Disabled"
  storage_tier   = "Standard"
  versioning     = "Enabled"
  freeform_tags  = local.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_objectstorage_object_lifecycle_policy" "backups" {
  namespace = data.oci_objectstorage_namespace.tenancy.namespace
  bucket    = oci_objectstorage_bucket.backups.name

  rules {
    action      = "DELETE"
    is_enabled  = true
    name        = "delete-current-backups-after-14-days"
    target      = "objects"
    time_amount = 14
    time_unit   = "DAYS"
  }

  rules {
    action      = "DELETE"
    is_enabled  = true
    name        = "delete-previous-backup-versions-after-21-days"
    target      = "previous-object-versions"
    time_amount = 21
    time_unit   = "DAYS"
  }

  rules {
    action      = "ABORT"
    is_enabled  = true
    name        = "abort-incomplete-multipart-uploads-after-1-day"
    target      = "multipart-uploads"
    time_amount = 1
    time_unit   = "DAYS"
  }

  depends_on = [oci_identity_policy.object_storage_lifecycle]
}
