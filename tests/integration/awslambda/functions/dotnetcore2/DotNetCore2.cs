using System.IO;
using Amazon.Lambda.Core;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace DotNetCore2.Lambda
{
    public class Function
    {
        public object SimpleFunctionHandler(Stream input, ILambdaContext context)
        {
            context.Logger.Log("Running .NET Core 2.0 Lambda");
            return new { };
        }
    }
}
