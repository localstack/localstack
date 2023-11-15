require 'aws-sdk'  # v2: require 'aws-sdk'

def setup_client(should_configure)
  if should_configure
    return Aws::SQS::Client.new(region: 'us-east-1', endpoint: ENV['AWS_ENDPOINT_URL'], credentials: Aws::Credentials.new('test', 'test'))
  else
    return Aws::SQS::Client.new(region: 'us-east-1', credentials: Aws::Credentials.new('test', 'test'))
  end
end

def handler(event:, context:)
  sqs_client = setup_client(ENV["CONFIGURE_CLIENT"] == "1")
  sqs_client.list_queues()
  return "ok"
end
