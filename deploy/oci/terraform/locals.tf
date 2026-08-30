locals {
  deployment_compartment_id = var.create_compartment ? oci_identity_compartment.clixor_prod[0].id : var.compartment_ocid
  availability_domain       = data.oci_identity_availability_domains.available.availability_domains[var.availability_domain_index].name

  # Source-controlled pin for the Ubuntu 24.04 ARM64 image currently used by
  # clixor-prod-1 in us-phoenix-1. A "latest image" data source can silently
  # change source_id and trigger a disruptive boot-volume replacement. Upgrade
  # this OCID only through a separately reviewed host-replacement procedure.
  ubuntu_image_id = "ocid1.image.oc1.phx.aaaaaaaa2xgl5y6skitgkee2aiprxzydi3nnxlqojrxtcifdb5d6a3djexuq"

  required_tags = {
    Project       = "Clixor"
    Environment   = "production"
    ManagedBy     = "Terraform"
    CostGuardrail = "AlwaysFree"
  }
  tags = merge(local.required_tags, var.freeform_tags)
}
