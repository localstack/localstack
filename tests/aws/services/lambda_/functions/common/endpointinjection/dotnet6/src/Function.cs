using System.Collections;
using System.Threading.Tasks;
using System;

using Amazon.Lambda.Core;
using Amazon.Runtime;
using Amazon.SQS;
using Amazon.SQS.Model;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace dotnet6
{

    public class Function
    {

        public async Task FunctionHandler(object input, ILambdaContext context)
        {
            AmazonSQSConfig sqsClientConfig = new AmazonSQSConfig();
            string endpointUrl = Environment.GetEnvironmentVariable("AWS_ENDPOINT_URL");
            if (endpointUrl != null) {
                sqsClientConfig = new AmazonSQSConfig
                {
                    ServiceURL = endpointUrl,
                };
            }
            AmazonSQSClient sqsClient = new AmazonSQSClient(sqsClientConfig);

            ListQueuesRequest request = new ListQueuesRequest();
            ListQueuesResponse response = await sqsClient.ListQueuesAsync(request);
            Console.WriteLine("QueueUrls: [" + string.Join(", ", response.QueueUrls) + "]");
        }
    }
}
