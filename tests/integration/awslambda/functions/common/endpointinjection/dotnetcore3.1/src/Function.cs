using System.Collections;
using System.Collections.Generic;
using System.Threading.Tasks;
using System;
using System.Linq;

using Amazon.Lambda.Core;
using Amazon.Runtime;
using Amazon.SQS;
using Amazon.SQS.Model;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace dotnetcore31
{

    public class Function
    {

        public async Task FunctionHandler(object input, ILambdaContext context)
        {
            AmazonSQSClient sqsClient;
            if (Environment.GetEnvironmentVariable("CONFIGURE_CLIENT") == "1") {
                var endpoint = Environment.GetEnvironmentVariable("LOCALSTACK_HOSTNAME");
                sqsClient = new AmazonSQSClient(new AmazonSQSConfig()
                    {
                        ServiceURL = $"http://{endpoint}:4566",
                        AuthenticationRegion = "us-east-1",
                    }
                );
            } else {
                sqsClient = new AmazonSQSClient(new AmazonSQSConfig()
                    {
                        AuthenticationRegion = "us-east-1",
                    }
                );
            }

            await sqsClient.ListQueuesAsync("");
        }
    }
}
