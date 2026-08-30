data "oci_identity_availability_domains" "available" {
  compartment_id = var.tenancy_ocid
}

data "oci_core_images" "ubuntu_arm64" {
  compartment_id           = var.tenancy_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04"
  shape                    = var.instance_shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

resource "oci_core_instance" "clixor" {
  availability_domain = local.availability_domain
  compartment_id      = local.deployment_compartment_id
  display_name        = "clixor-prod-1"
  shape               = var.instance_shape

  shape_config {
    ocpus         = var.instance_ocpus
    memory_in_gbs = var.instance_memory_gbs
  }

  create_vnic_details {
    assign_public_ip = false
    display_name     = "clixor-prod-1-vnic"
    hostname_label   = "clixor-prod-1"
    nsg_ids          = [oci_core_network_security_group.app.id]
    subnet_id        = oci_core_subnet.private.id
  }

  source_details {
    source_type             = "image"
    source_id               = local.ubuntu_image_id
    boot_volume_size_in_gbs = var.boot_volume_size_gbs
    boot_volume_vpus_per_gb = 10
  }

  instance_options {
    are_legacy_imds_endpoints_disabled = true
  }

  availability_config {
    recovery_action = "RESTORE_INSTANCE"
  }

  launch_options {
    is_consistent_volume_naming_enabled = true
    is_pv_encryption_in_transit_enabled = true
    network_type                        = "PARAVIRTUALIZED"
  }

  agent_config {
    is_management_disabled = false
    is_monitoring_disabled = false

    # Managed SSH sessions require this plugin; OCI images leave it disabled by
    # default even when Oracle Cloud Agent management itself is enabled.
    plugins_config {
      name          = "Bastion"
      desired_state = "ENABLED"
    }
  }

  metadata = {
    ssh_authorized_keys = trimspace(var.ssh_public_key)
    user_data = base64encode(templatefile("${path.module}/cloud-init.yaml.tftpl", {
      data_device                   = var.data_device
      data_volume_size_gbs          = var.data_volume_size_gbs
      mount_data_script             = file("${path.module}/clixor-mount-data.sh")
      mount_data_unit               = file("${path.module}/clixor-data-volume.service")
      bastion_private_endpoint_cidr = "${oci_bastion_bastion.clixor.private_endpoint_ip_address}/32"
    }))
  }

  preserve_boot_volume = false
  freeform_tags        = local.tags

  lifecycle {
    # Cloud-init is a first-boot contract. Changing user_data on an existing OCI
    # instance is ForceNew in the provider, so reconcile the live host through
    # the reviewed operational scripts instead of unexpectedly replacing it.
    ignore_changes = [metadata["user_data"]]

    precondition {
      condition     = var.boot_volume_size_gbs + var.data_volume_size_gbs <= 200
      error_message = "Boot and data volumes together must not exceed the 200-GB Always Free block-volume allowance."
    }

    precondition {
      condition     = length(data.oci_core_images.ubuntu_arm64.images) > 0
      error_message = "No Ubuntu 24.04 ARM64 image compatible with VM.Standard.A1.Flex was found in this region."
    }

    precondition {
      condition     = var.availability_domain_index < length(data.oci_identity_availability_domains.available.availability_domains)
      error_message = "availability_domain_index is outside the tenancy's availability-domain list."
    }
  }
}

resource "oci_core_volume" "clixor_data" {
  availability_domain  = local.availability_domain
  compartment_id       = local.deployment_compartment_id
  display_name         = "clixor-prod-data"
  size_in_gbs          = var.data_volume_size_gbs
  vpus_per_gb          = 10
  is_auto_tune_enabled = false
  freeform_tags        = local.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_core_volume_attachment" "clixor_data" {
  attachment_type = "paravirtualized"
  display_name    = "clixor-prod-data-attachment"
  instance_id     = oci_core_instance.clixor.id
  volume_id       = oci_core_volume.clixor_data.id
  device          = var.data_device
  is_read_only    = false
}
