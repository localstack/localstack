resource "aws_s3_bucket" "tf_bucket" {
  bucket = "tf-bucket"
  acl    = "public-read"

  tags = {
    Name        = "tf-bucket"
    Environment = "Dev"
  }
}
