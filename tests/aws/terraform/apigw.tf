variable "restapi_name" {
  type = string
}
resource "aws_api_gateway_rest_api" "service_api" {
  name               = var.restapi_name

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "execute-api:Invoke",
            "Resource": "*"
        }
    ]
}
EOF
}
