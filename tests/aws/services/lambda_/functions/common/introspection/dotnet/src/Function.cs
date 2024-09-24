using System.Collections;
using System.Collections.Generic;
using System;
using System.Linq;

using Amazon.Lambda.Core;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Dotnet
{
    public class LambdaResponse
    {
        public IDictionary<string, string> environment { get; set; }
        public IDictionary<string, string> ctx { get; set; }
        public List<string> packages { get; set; }
    }
    public class Function
    {

        public LambdaResponse FunctionHandler(object input, ILambdaContext context)
        {
            return new LambdaResponse{
                environment = Environment.GetEnvironmentVariables().Cast<DictionaryEntry>().ToDictionary(kvp => (string) kvp.Key, kvp => (string) kvp.Value),
                ctx = new Dictionary<string, string>(){
                    {"function_name", context.FunctionName},
                    {"function_version", context.FunctionVersion},
                    {"invoked_function_arn", context.InvokedFunctionArn},
                    {"memory_limit_in_mb", context.MemoryLimitInMB.ToString()},
                    {"aws_request_id", context.AwsRequestId},
                    {"log_group_name", context.LogGroupName},
                    {"log_stream_name", context.LogStreamName},
                    {"remaining_time_in_millis", context.RemainingTime.Milliseconds.ToString()}
                },
                packages = new List<string>()
            };
        }
    }
}
