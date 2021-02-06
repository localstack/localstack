resource "aws_s3_bucket" "tf_bucket" {
  bucket = "tf-bucket"
  acl    = "public-read"

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "PUT", "POST"]
    allowed_origins = ["*"]
    expose_headers  = ["ETag", "x-amz-version-id"]
    max_age_seconds = 3000
  }

  versioning {
    enabled = true
  }

  tags = {
    Name        = "tf-bucket"
    Environment = "Dev"
  }
}
