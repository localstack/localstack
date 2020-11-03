resource "aws_lambda_function" "tf_lambda" {
  filename      = "../lambdas/dotnetcore2/dotnetcore2.zip"
  function_name = "tf-lambda"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "DotNetCore2::DotNetCore2.Lambda.Function::SimpleFunctionHandler"

  source_code_hash = filebase64sha256("../lambdas/dotnetcore2/dotnetcore2.zip")

  runtime = "dotnetcore2.0"
}