variable "tenancy_ocid" {
  description = "OCI tenancy OCID. Resource Manager prepopulates this value."
  type        = string
}

variable "compartment_ocid" {
  description = "Parent compartment for the optional ClixorProd child compartment. Resource Manager prepopulates this value."
  type        = string
}

variable "region" {
  description = "OCI home region. Always Free A1 capacity must be created in the home region."
  type        = string
  default     = "us-phoenix-1"

  validation {
    condition     = var.region == "us-phoenix-1"
    error_message = "This stack is restricted to the tenancy home region, us-phoenix-1, to preserve Always Free eligibility."
  }
}

variable "create_compartment" {
  description = "Create a dedicated child compartment named by compartment_name."
  type        = bool
  default     = true
}

variable "compartment_name" {
  description = "Dedicated application compartment name."
  type        = string
  default     = "ClixorProd"

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9_-]{1,99}$", var.compartment_name))
    error_message = "compartment_name must start with a letter and contain only letters, digits, underscores, or hyphens."
  }
}

variable "availability_domain_index" {
  description = "Zero-based availability-domain index. Change this and re-plan if Oracle reports A1 host-capacity exhaustion."
  type        = number
  default     = 0

  validation {
    condition     = var.availability_domain_index >= 0 && floor(var.availability_domain_index) == var.availability_domain_index
    error_message = "availability_domain_index must be a non-negative integer."
  }
}

variable "ssh_public_key" {
  description = "Existing OpenSSH public key for the ubuntu user. This is not a secret."
  type        = string
  sensitive   = false

  validation {
    condition     = can(regex("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+(?: .*)?$", trimspace(var.ssh_public_key)))
    error_message = "ssh_public_key must be one valid OpenSSH public key."
  }
}

variable "admin_cidr" {
  description = "Administrator public IPv4 address in /32 CIDR notation allowed to create Bastion sessions."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.admin_cidr)) && endswith(var.admin_cidr, "/32")
    error_message = "admin_cidr must be a single IPv4 address expressed as a /32 CIDR."
  }
}

variable "instance_shape" {
  description = "Compute shape. The stack intentionally permits only the Always Free Ampere A1 shape."
  type        = string
  default     = "VM.Standard.A1.Flex"

  validation {
    condition     = var.instance_shape == "VM.Standard.A1.Flex"
    error_message = "Only VM.Standard.A1.Flex is permitted by this Always Free stack."
  }
}

variable "instance_ocpus" {
  description = "A1 OCPUs. Current Always Free continuous allowance is 2 OCPUs total."
  type        = number
  default     = 2

  validation {
    condition     = var.instance_ocpus > 0 && var.instance_ocpus <= 2
    error_message = "instance_ocpus must be greater than 0 and no more than the 2-OCPU Always Free allowance."
  }
}

variable "instance_memory_gbs" {
  description = "A1 memory in GB. Current Always Free continuous allowance is 12 GB total."
  type        = number
  default     = 12

  validation {
    condition     = var.instance_memory_gbs > 0 && var.instance_memory_gbs <= 12
    error_message = "instance_memory_gbs must be greater than 0 and no more than the 12-GB Always Free allowance."
  }
}

variable "boot_volume_size_gbs" {
  description = "Balanced boot volume size in GB."
  type        = number
  default     = 50

  validation {
    condition     = var.boot_volume_size_gbs >= 50 && var.boot_volume_size_gbs <= 100 && floor(var.boot_volume_size_gbs) == var.boot_volume_size_gbs
    error_message = "boot_volume_size_gbs must be a whole number between 50 and 100 GB."
  }
}

variable "data_volume_size_gbs" {
  description = "Balanced data volume size in GB, mounted at /srv/clixor by host bootstrap."
  type        = number
  default     = 100

  validation {
    condition     = var.data_volume_size_gbs >= 50 && var.data_volume_size_gbs <= 150 && floor(var.data_volume_size_gbs) == var.data_volume_size_gbs
    error_message = "data_volume_size_gbs must be a whole number between 50 and 150 GB."
  }
}

variable "data_device" {
  description = "Stable OCI device path for the first paravirtualized attached volume."
  type        = string
  default     = "/dev/oracleoci/oraclevdb"

  validation {
    condition     = can(regex("^/dev/oracleoci/oraclevd[b-z]$", var.data_device))
    error_message = "data_device must select a non-boot OCI device from /dev/oracleoci/oraclevdb through /dev/oracleoci/oraclevdz."
  }
}

variable "backup_bucket_name" {
  description = "Private Object Storage bucket for encrypted logical backups."
  type        = string
  default     = "clixor-prod-backups"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{1,256}$", var.backup_bucket_name))
    error_message = "backup_bucket_name contains unsupported characters."
  }
}

variable "media_bucket_name" {
  description = "Private Object Storage bucket used as Clixor's primary application-media store."
  type        = string
  default     = "clixor-prod-media"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{1,256}$", var.media_bucket_name))
    error_message = "media_bucket_name contains unsupported characters."
  }

}

variable "vcn_cidr" {
  description = "Clixor production VCN CIDR."
  type        = string
  default     = "10.42.0.0/16"
}

variable "private_subnet_cidr" {
  description = "Regional private application subnet CIDR."
  type        = string
  default     = "10.42.10.0/24"
}

variable "freeform_tags" {
  description = "Additional non-sensitive tags merged into the required cost and ownership tags."
  type        = map(string)
  default     = {}
}

variable "create_mail_approved_sender" {
  description = "Create no-reply@mail.atlanteanz.com only after the output DKIM CNAME and SPF TXT records are public and OCI reports the DKIM state ACTIVE."
  type        = bool
  default     = false
}
