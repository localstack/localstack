terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 3.71.0, <= 3.79.0"
    }
  }

  required_version = "1.1.3"
}
