terraform {
  required_providers {
    # Note: pinning version for now, as 3.64.0 seems to be causing issues in our CI builds
    version = "3.63.0"
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "aws_mock_key"
  secret_key                  = "aws_mock_key"
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
