using Amazon.Lambda.Core;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace dotnet8
{
    public class Function
    {

        public object FunctionHandler(object input, ILambdaContext context)
        {
            return input;
        }
    }
}
