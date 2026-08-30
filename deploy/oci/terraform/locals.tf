locals {
  deployment_compartment_id = var.create_compartment ? oci_identity_compartment.clixor_prod[0].id : var.compartment_ocid
  availability_domain       = data.oci_identity_availability_domains.available.availability_domains[var.availability_domain_index].name
  ubuntu_image_id           = data.oci_core_images.ubuntu_arm64.images[0].id

  required_tags = {
    Project       = "Clixor"
    Environment   = "production"
    ManagedBy     = "Terraform"
    CostGuardrail = "AlwaysFree"
  }
  tags = merge(local.required_tags, var.freeform_tags)
}
