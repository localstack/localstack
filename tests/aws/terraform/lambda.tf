variable "function_name" {
  type = string
}

resource "aws_lambda_function" "tf_lambda" {
  filename      = "../awslambda/functions/echo.zip"
  function_name = var.function_name
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.handler"

  source_code_hash = filebase64sha256("../awslambda/functions/echo.zip")

  runtime = "python3.8"
}
