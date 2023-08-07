variable "region_name" {
  type = string
}

provider "aws" {
  region                      = var.region_name
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  s3_force_path_style         = true
  endpoints {
    acm        = "http://localhost:4566"
    apigateway = "http://localhost:4566"
    dynamodb   = "http://localhost:4566"
    ec2        = "http://localhost:4566"
    iam        = "http://localhost:4566"
    lambda     = "http://localhost:4566"
    kms        = "http://localhost:4566"
    route53    = "http://localhost:4566"
    s3         = "http://localhost:4566"
    sqs        = "http://localhost:4566"
  }
}
