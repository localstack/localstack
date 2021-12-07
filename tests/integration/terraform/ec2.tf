resource "aws_vpc" "main-vpc" {
  cidr_block       = "10.5.0.0/16"
  instance_tenancy = "default"
  tags = {
    k1 = "value1"
  }
}

variable "sg_name" {
  type = string
}
resource "aws_security_group" "test-sg" {
  name        = var.sg_name
  description = "Test Security Group test-sg"
  vpc_id      = aws_vpc.main-vpc.id
}
