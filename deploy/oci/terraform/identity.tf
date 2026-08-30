resource "oci_identity_compartment" "clixor_prod" {
  count = var.create_compartment ? 1 : 0

  compartment_id = var.compartment_ocid
  name           = var.compartment_name
  description    = "Clixor production infrastructure managed by Terraform"
  enable_delete  = false
  freeform_tags  = local.tags
}

resource "oci_identity_dynamic_group" "clixor_hosts" {
  compartment_id = var.tenancy_ocid
  name           = "ClixorProdHosts"
  description    = "Compute instances authorized for Clixor runtime secrets, media, and backups"
  matching_rule  = "instance.id = '${oci_core_instance.clixor.id}'"
  freeform_tags  = local.tags
}

resource "oci_identity_policy" "instance_principal" {
  compartment_id = var.tenancy_ocid
  name           = "ClixorProdHostAccess"
  description    = "Least-privilege instance-principal access for Clixor production"

  statements = [
    "Allow dynamic-group ${oci_identity_dynamic_group.clixor_hosts.name} to read secret-bundles in compartment id ${local.deployment_compartment_id}",
    "Allow dynamic-group ${oci_identity_dynamic_group.clixor_hosts.name} to read buckets in compartment id ${local.deployment_compartment_id} where target.bucket.name = '${oci_objectstorage_bucket.backups.name}'",
    "Allow dynamic-group ${oci_identity_dynamic_group.clixor_hosts.name} to manage objects in compartment id ${local.deployment_compartment_id} where all {target.bucket.name = '${oci_objectstorage_bucket.backups.name}', any {request.permission = 'OBJECT_CREATE', request.permission = 'OBJECT_INSPECT', request.permission = 'OBJECT_READ'}}",
    "Allow dynamic-group ${oci_identity_dynamic_group.clixor_hosts.name} to read buckets in compartment id ${local.deployment_compartment_id} where target.bucket.name = '${oci_objectstorage_bucket.media.name}'",
    "Allow dynamic-group ${oci_identity_dynamic_group.clixor_hosts.name} to manage buckets in compartment id ${local.deployment_compartment_id} where all {target.bucket.name = '${oci_objectstorage_bucket.media.name}', request.permission = 'PAR_MANAGE'}",
    "Allow dynamic-group ${oci_identity_dynamic_group.clixor_hosts.name} to manage objects in compartment id ${local.deployment_compartment_id} where target.bucket.name = '${oci_objectstorage_bucket.media.name}'",
  ]

  freeform_tags = local.tags
}

resource "oci_identity_policy" "object_storage_lifecycle" {
  compartment_id = var.tenancy_ocid
  name           = "ClixorObjectStorageLifecycle"
  description    = "Bucket-scoped Object Storage service permissions for Clixor lifecycle rules"

  statements = concat(
    [
      for permission in ["BUCKET_INSPECT", "BUCKET_READ", "OBJECT_INSPECT", "OBJECT_DELETE"] :
      "Allow service objectstorage-${var.region} to manage object-family in compartment id ${local.deployment_compartment_id} where all {target.bucket.name = '${oci_objectstorage_bucket.media.name}', request.permission = '${permission}'}"
    ],
    [
      for permission in ["BUCKET_INSPECT", "BUCKET_READ", "OBJECT_INSPECT", "OBJECT_DELETE", "OBJECT_VERSION_DELETE"] :
      "Allow service objectstorage-${var.region} to manage object-family in compartment id ${local.deployment_compartment_id} where all {target.bucket.name = '${oci_objectstorage_bucket.backups.name}', request.permission = '${permission}'}"
    ]
  )

  freeform_tags = local.tags
}
