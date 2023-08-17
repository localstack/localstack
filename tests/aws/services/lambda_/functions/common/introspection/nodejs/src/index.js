exports.handler = async function(event, context) {
    return {environment: process.env, ctx: {
            function_name: context.functionName,
            function_version: context.functionVersion,
            invoked_function_arn: context.invokedFunctionArn,
            memory_limit_in_mb: context.memoryLimitInMb,
            aws_request_id: context.awsRequestId,
            log_group_name: context.logGroupName,
            log_stream_name: context.logStreamName,
            remaining_time_in_millis: context.getRemainingTimeInMillis(),
        }, packages: []}
};
