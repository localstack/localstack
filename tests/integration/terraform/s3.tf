resource "aws_s3_bucket" "b" {
<<<<<<< HEAD
  bucket = "test-bucket"
  acl    = "public-read"

  tags = {
    Name        = "test-bucket"
=======
  bucket = "tf-bucket"
  acl    = "public-read"

  tags = {
    Name        = "tf-bucket"
>>>>>>> 65d4433e215bc383c49fcd12cdc5b09f3259b392
    Environment = "Dev"
  }
}
