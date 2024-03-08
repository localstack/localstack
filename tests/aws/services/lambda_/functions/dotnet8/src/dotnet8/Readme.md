# AWS Lambda Function Project for Integration Testing

## Here are some steps to follow to get started from the command line:

You can package this testing app using the [Amazon.Lambda.Tools Global Tool](https://github.com/aws/aws-extensions-for-dotnet-cli#aws-lambda-amazonlambdatools) from the command line.

Install Amazon.Lambda.Tools Global Tools if not already installed.
```
    dotnet tool install -g Amazon.Lambda.Tools
```

If already installed check if new version is available.
```
    dotnet tool update -g Amazon.Lambda.Tools
```

Create zip file for integration test
```
    cd functions/dotnet8/src/dotnet8
    dotnet lambda package -o ../../dotnet8.zip
```
