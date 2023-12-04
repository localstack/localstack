# SDK v2: https://docs.aws.amazon.com/sdk-for-ruby/v2/api/
require 'aws-sdk'


def handler(event:, context:)
  sqs_client = Aws::SQS::Client.new(endpoint: ENV['AWS_ENDPOINT_URL'])
  queues = sqs_client.list_queues()
  puts("queues=#{queues}")
  return "ok"
end
