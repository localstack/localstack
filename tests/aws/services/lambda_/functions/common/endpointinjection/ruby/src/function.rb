# SDK v2: https://docs.aws.amazon.com/sdk-for-ruby/v2/api/
require 'aws-sdk'


def handler(event:, context:)
  config = {}
  if ENV['AWS_ENDPOINT_URL']
    config['endpoint'] = ENV['AWS_ENDPOINT_URL']
  end
  sqs_client = Aws::SQS::Client.new(config)
  queues = sqs_client.list_queues()
  puts("queues=#{queues}")
  return "ok"
end
