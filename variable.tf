variable "ami" {
  default     = "ami-0f0f1c02e5e4d9d9f"
  description = "ami for ec2"
}

variable "server_key" {
  default     = "~/keypair/key.pub"
  description = "this is the path to my pub key"
}


variable "server_priv_key" {
  default     = "~/keypair/key"
  description = "this is the path to my pub key"
}

variable "port_mysql_database" {
  default = 3306
}

variable "port_http" {
  default = 80
}

variable "port_ssh" {
  default = 22
}

variable "port_proxy" {
  default = 8080
}

variable "sonar_port" {
  default = 9000
}

variable "egress" {
  default = "0"
}

variable "sonar_ami" {
  default = "ami-096800910c1b781ba"
}


# variable "username" {
#   default = "pacdadmin"
# }

# variable "passwd" {
#   default = "Admin123"
# }

variable "instance_type" {
  default = "t2.medium"
}

variable "database_username" {
  default = "pacdb"
}

variable "db_password" {
  default = "Admin123"
}


