variable "sqs_name" {
  type = string
}
resource "aws_sqs_queue" "tf_queue" {
  name                      = var.sqs_name
  delay_seconds             = 90
  max_message_size          = 2048
  message_retention_seconds = 86400
  receive_wait_time_seconds = 10

  tags = {
    Name        = var.sqs_name
    Environment = "Dev"
  }
}
