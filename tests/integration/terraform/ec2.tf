resource "aws_vpc" "main-vpc" {
  cidr_block       = "10.5.0.0/16"
  instance_tenancy = "default"
  tags = {
    k1 = "value1"
  }
}

resource "aws_security_group" "test-sg-5249" {
  name        = "test-sg-5249"
  description = "Test Security Group test-sg-5249"
  vpc_id      = aws_vpc.main-vpc.id
}
