data "oci_core_services" "oracle_services" {
  filter {
    name   = "name"
    values = ["All .* Services In Oracle Services Network"]
    regex  = true
  }
}

resource "oci_core_vcn" "clixor" {
  compartment_id = local.deployment_compartment_id
  cidr_blocks    = [var.vcn_cidr]
  display_name   = "clixor-prod-vcn"
  dns_label      = "clixorprod"
  freeform_tags  = local.tags
}

resource "oci_core_nat_gateway" "outbound" {
  compartment_id = local.deployment_compartment_id
  vcn_id         = oci_core_vcn.clixor.id
  display_name   = "clixor-prod-nat"
  block_traffic  = false
  freeform_tags  = local.tags
}

resource "oci_core_service_gateway" "oracle_services" {
  compartment_id = local.deployment_compartment_id
  vcn_id         = oci_core_vcn.clixor.id
  display_name   = "clixor-prod-service-gateway"

  services {
    service_id = data.oci_core_services.oracle_services.services[0].id
  }

  freeform_tags = local.tags
}

resource "oci_core_route_table" "private" {
  compartment_id = local.deployment_compartment_id
  vcn_id         = oci_core_vcn.clixor.id
  display_name   = "clixor-prod-private-routes"

  route_rules {
    destination       = data.oci_core_services.oracle_services.services[0].cidr_block
    destination_type  = "SERVICE_CIDR_BLOCK"
    network_entity_id = oci_core_service_gateway.oracle_services.id
    description       = "Private access to OCI services"
  }

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_nat_gateway.outbound.id
    description       = "Outbound-only internet access"
  }

  freeform_tags = local.tags
}

resource "oci_core_security_list" "private" {
  compartment_id = local.deployment_compartment_id
  vcn_id         = oci_core_vcn.clixor.id
  display_name   = "clixor-prod-private-security-list"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
    description = "Outbound traffic only; the route table controls public versus OCI-service paths"
  }

  freeform_tags = local.tags
}

resource "oci_core_subnet" "private" {
  compartment_id             = local.deployment_compartment_id
  vcn_id                     = oci_core_vcn.clixor.id
  cidr_block                 = var.private_subnet_cidr
  display_name               = "clixor-app-private"
  dns_label                  = "app"
  prohibit_public_ip_on_vnic = true
  route_table_id             = oci_core_route_table.private.id
  security_list_ids          = [oci_core_security_list.private.id]
  freeform_tags              = local.tags
}

resource "oci_core_network_security_group" "app" {
  compartment_id = local.deployment_compartment_id
  vcn_id         = oci_core_vcn.clixor.id
  display_name   = "clixor-prod-app-nsg"
  freeform_tags  = local.tags
}

resource "oci_core_network_security_group_security_rule" "ssh_from_bastion_endpoint" {
  network_security_group_id = oci_core_network_security_group.app.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = "${oci_bastion_bastion.clixor.private_endpoint_ip_address}/32"
  source_type               = "CIDR_BLOCK"
  description               = "SSH from the single OCI Bastion private endpoint"

  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}

resource "oci_core_network_security_group_security_rule" "outbound" {
  network_security_group_id = oci_core_network_security_group.app.id
  direction                 = "EGRESS"
  protocol                  = "all"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
  description               = "Outbound Cloudflare, APNs, Telnyx, package, and OCI API traffic"
}

resource "oci_bastion_bastion" "clixor" {
  bastion_type                 = "standard"
  compartment_id               = local.deployment_compartment_id
  target_subnet_id             = oci_core_subnet.private.id
  client_cidr_block_allow_list = [var.admin_cidr]
  max_session_ttl_in_seconds   = 10800
  name                         = "clixor-prod-bastion"
  dns_proxy_status             = "DISABLED"
  freeform_tags                = local.tags
}
