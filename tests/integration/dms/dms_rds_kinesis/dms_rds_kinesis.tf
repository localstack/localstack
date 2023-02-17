terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
    }
  }

  required_version = "1.2.5"
}

provider "aws" {
  region  = var.region_name
  profile = "ls"
}

locals {
  tags = {
    Name        = "dms-${random_string.test.result}"
    Environment = "test"
    Terraform   = "true"
    TerraformID = random_string.test.result
  }
}

variable "region_name" {
  type = string
}

variable "db_name" {
  description = "database name"
  type        = string
}

variable "db_pass" {
  description = "db password"
  type        = string
  sensitive   = true
}

variable "db_user" {
  description = "db username"
  type        = string
}

variable "client_ip" {
    description = "client ip"
    type        = string
}

resource "random_string" "test" {
  length  = 8
  special = false
  upper   = false
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "dms_vpc" {
  cidr_block           = "10.0.0.0/24"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = local.tags
}


resource "aws_subnet" "subnet_a" {
  vpc_id            = aws_vpc.dms_vpc.id
  cidr_block        = "10.0.0.0/26"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = local.tags
}

resource "aws_subnet" "subnet_b" {
  vpc_id            = aws_vpc.dms_vpc.id
  cidr_block        = "10.0.0.64/26"
  availability_zone = data.aws_availability_zones.available.names[1]
  tags              = local.tags
}

resource "aws_internet_gateway" "dms_igw" {
  vpc_id = aws_vpc.dms_vpc.id
  tags   = local.tags
}

resource "aws_route_table" "dms_route_table" {
  vpc_id = aws_vpc.dms_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.dms_igw.id
  }
  tags = local.tags
}

resource "aws_route_table_association" "subnet_a" {
  subnet_id      = aws_subnet.subnet_a.id
  route_table_id = aws_route_table.dms_route_table.id
}

resource "aws_route_table_association" "subnet_b" {
  subnet_id      = aws_subnet.subnet_b.id
  route_table_id = aws_route_table.dms_route_table.id
}

resource "aws_db_subnet_group" "dms_subnet_group" {
  name       = local.tags["Name"]
  subnet_ids = [aws_subnet.subnet_a.id, aws_subnet.subnet_b.id]

  tags = local.tags
}

resource "aws_security_group" "dms_sg" {
  name_prefix = "dms"
  description = "Security group for DMS"
  vpc_id      = aws_vpc.dms_vpc.id
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [var.client_ip, aws_vpc.dms_vpc.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

resource "aws_db_instance" "dms_db" {
  allocated_storage           = 20
  engine                      = "mysql"
  engine_version              = "8.0"
  instance_class              = "db.t3.micro"
  username                    = var.db_user
  password                    = var.db_pass
  db_name                     = var.db_name
  parameter_group_name        = aws_db_parameter_group.dms_db_parameter_group.name
  skip_final_snapshot         = true
  vpc_security_group_ids      = [aws_security_group.dms_sg.id]
  db_subnet_group_name        = aws_db_subnet_group.dms_subnet_group.name
  publicly_accessible         = true
  allow_major_version_upgrade = false
  auto_minor_version_upgrade  = false
  backup_retention_period     = 0
  identifier                  = local.tags["Name"]
  storage_encrypted           = false
  tags                        = local.tags
}

resource "aws_db_parameter_group" "dms_db_parameter_group" {
  name   = local.tags["Name"]
  family = "mysql8.0"

  parameter {
    name  = "binlog_format"
    value = "ROW"
  }

  parameter {
    name  = "binlog_checksum"
    value = "NONE"
  }

  lifecycle {
    create_before_destroy = true
  }
  tags = local.tags
}

resource "aws_iam_role" "dms_cloudwatch_logs_role" {
  name = "${local.tags["Name"]}-cloudwatch-log-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "dms.amazonaws.com"
        }
      }
    ]
  })
  managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AmazonDMSCloudWatchLogsRole"]
  tags                = local.tags
}

resource "aws_iam_role" "dms_vpc_role" {
  name = "${local.tags["Name"]}-vpc-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "dms.amazonaws.com"
        }
      }
    ]
  })
  managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AmazonDMSVPCManagementRole"]
  tags                = local.tags
}

resource "aws_iam_role" "kinesis_target_role" {
  name = "${local.tags["Name"]}-kinesis-target-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "dms.amazonaws.com"
        }
      }
    ]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "kinesis_target_policy" {
  name = "${local.tags["Name"]}-kinesis-target-policy"
  role = aws_iam_role.kinesis_target_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "kinesis:DescribeStream",
          "kinesis:PutRecord",
          "kinesis:PutRecords",
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_kinesis_stream" "dms_kinesis_stream" {
  name             = local.tags["Name"]
  shard_count      = 1
  retention_period = 24
  tags             = local.tags
}


resource "aws_dms_replication_subnet_group" "dms_replication_subnet_group" {
  replication_subnet_group_id          = local.tags["Name"]
  replication_subnet_group_description = local.tags["Name"]
  subnet_ids                           = [aws_subnet.subnet_a.id, aws_subnet.subnet_b.id]
  tags                                 = local.tags
}

resource "aws_dms_replication_instance" "dms_replication_instance" {
  replication_instance_id     = local.tags["Name"]
  replication_instance_class  = "dms.t3.micro"
  allocated_storage           = 20
  publicly_accessible         = true
  multi_az                    = false
  auto_minor_version_upgrade  = false
  allow_major_version_upgrade = false
  apply_immediately           = true
  replication_subnet_group_id = aws_dms_replication_subnet_group.dms_replication_subnet_group.replication_subnet_group_id
  vpc_security_group_ids      = [aws_security_group.dms_sg.id]
  availability_zone           = aws_subnet.subnet_a.availability_zone
  tags                        = local.tags
}

resource "aws_dms_endpoint" "dms_source_endpoint" {
  endpoint_id   = "${local.tags["Name"]}-source"
  endpoint_type = "source"
  engine_name   = "mysql"
  username      = var.db_user
  password      = var.db_pass
  server_name   = aws_db_instance.dms_db.address
  port          = 3306
  database_name = var.db_name
  tags          = local.tags
}

resource "aws_dms_endpoint" "dms_target_endpoint" {
  endpoint_id   = "${local.tags["Name"]}-target"
  endpoint_type = "target"
  engine_name   = "kinesis"
  kinesis_settings {
    stream_arn              = aws_kinesis_stream.dms_kinesis_stream.arn
    message_format          = "json"
    service_access_role_arn = aws_iam_role.kinesis_target_role.arn
  }
  tags = local.tags
}

resource "aws_dms_replication_task" "dms_replication_task" {
  replication_task_id      = local.tags["Name"]
  migration_type           = "full-load"
  replication_instance_arn = aws_dms_replication_instance.dms_replication_instance.replication_instance_arn
  source_endpoint_arn      = aws_dms_endpoint.dms_source_endpoint.endpoint_arn
  target_endpoint_arn      = aws_dms_endpoint.dms_target_endpoint.endpoint_arn
  table_mappings = jsonencode({
    "rules" : [
      {
        "rule-type" : "selection",
        "rule-id" : "1",
        "rule-name" : "1",
        "object-locator" : {
          "schema-name" : "test",
          "table-name" : "test"
        },
        "rule-action" : "include"
      }
    ]
  })
  replication_task_settings = jsonencode({
    "TargetMetadata" : {
      "TargetSchema" : "test",
      "SupportLobs" : true
    }
  })
  tags = local.tags
}

output "rds_endpoint" {
  value       = aws_db_instance.dms_db.address
  description = "RDS endpoint"
}

output "kinesis_stream_arn" {
  value       = aws_kinesis_stream.dms_kinesis_stream.arn
  description = "Kinesis stream ARN"
}

output "replication_task_arn" {
  value       = aws_dms_replication_task.dms_replication_task.replication_task_arn
  description = "Replication task ARN"
}
