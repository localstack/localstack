using System.IO;

using Amazon.Lambda.Core;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]
namespace dotnet6
{
    public class Function
    {

        /// <summary>
        /// A simple function that returns an empty payload
        /// </summary>
        /// <param name="input"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public object FunctionHandler(Stream input, ILambdaContext context)
        {
            context.Logger.Log("Running .NET 6 Lambda");

            return new { };
        }
    }
}
