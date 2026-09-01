provider "oci" {
  # OCI Resource Manager supplies authentication. No API key belongs in this
  # configuration or its state.
  region = var.region
}
