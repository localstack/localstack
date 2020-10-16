resource "aws_s3_bucket" "b" {
  bucket = "tf-bucket"
  acl    = "public-read"

  tags = {
    Name        = "tf-bucket"
    Environment = "Dev"
  }
}
