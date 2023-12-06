package main

import (
	"context"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"os"
	"strconv"
	"strings"
)

type ReturnValue struct {
	Environment map[string]string `json:"environment"`
	Ctx         map[string]string `json:"ctx"`
	Packages    []string          `json:"packages"`
}

func HandleRequest(context context.Context, event map[string]string) (ReturnValue, error) {
	environment := make(map[string]string)
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		environment[pair[0]] = pair[1]
	}
	lc, _ := lambdacontext.FromContext(context)
	ctx := map[string]string{
		"function_name":        lambdacontext.FunctionName,
		"function_version":     lambdacontext.FunctionVersion,
		"invoked_function_arn": lc.InvokedFunctionArn,
		"memory_limit_in_mb":   strconv.Itoa(lambdacontext.MemoryLimitInMB),
		"aws_request_id":       lc.AwsRequestID,
		"log_group_name":       lambdacontext.LogGroupName,
		"log_stream_name":      lambdacontext.LogStreamName,
	}

	return ReturnValue{Environment: environment, Ctx: ctx, Packages: []string{}}, nil
}

func main() {
	lambda.Start(HandleRequest)
}
