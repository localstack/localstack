resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": "1"
    }
  ]
}
EOF
}

resource "aws_lambda_function" "tf_lambda" {
  filename      = "../lambdas/dotnetcore2/dotnetcore2.zip"
  function_name = "tf-lambda"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "DotNetCore2::DotNetCore2.Lambda.Function::SimpleFunctionHandler"

  source_code_hash = filebase64sha256("../lambdas/dotnetcore2/dotnetcore2.zip")

  runtime = "dotnetcore2.0"
}
