resource "aws_lambda_event_source_mapping" "tf_event_source_mapping" {
  event_source_arn = aws_sqs_queue.tf_queue.arn
  function_name = aws_lambda_function.tf_lambda.arn
}