resource "aws_s3_bucket" "b" {
  bucket = "test-bucket"
  acl    = "public-read"

  tags = {
    Name        = "test-bucket"
    Environment = "Dev"
  }
}
