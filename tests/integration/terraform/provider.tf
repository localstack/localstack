provider "aws" {
  region                      = "us-east-1"
  access_key                  = "aws_mock_key"
  secret_key                  = "aws_mock_key"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  s3_force_path_style         = true
  endpoints {
    s3 = "http://localhost:4566"
  }
}
