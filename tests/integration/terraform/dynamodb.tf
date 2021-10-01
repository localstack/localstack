resource "aws_kms_key" "tf_kms" {
  description             = "Terraform kms key"
  deletion_window_in_days = 10
}

resource "aws_dynamodb_table" "tf_dynamotable1" {
  hash_key       = "id"
  billing_mode   = "PAY_PER_REQUEST"
  name           = "tf_dynamotable1"
  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
    kms_key_arn = aws_kms_key.tf_kms.arn
  }
}

resource "aws_dynamodb_table" "tf_dynamotable2" {
  hash_key       = "id"
  billing_mode   = "PAY_PER_REQUEST"
  name           = "tf_dynamotable2"
  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled = false
    kms_key_arn = null
  }
}

resource "aws_dynamodb_table" "tf_dynamotable3" {
  hash_key       = "id"
  billing_mode   = "PAY_PER_REQUEST"
  name           = "tf_dynamotable3"
  attribute {
    name = "id"
    type = "S"
  }
}

