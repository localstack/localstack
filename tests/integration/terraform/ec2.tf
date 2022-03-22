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

resource "aws_security_group" "tls_allow" {
  name        = "tls_allow"
  description = "TF SG with ingress / egress rules"
  vpc_id      = aws_vpc.main-vpc.id

  ingress {
    description      = "TLS from VPC"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = [aws_vpc.main-vpc.cidr_block]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_tls"
  }
}
