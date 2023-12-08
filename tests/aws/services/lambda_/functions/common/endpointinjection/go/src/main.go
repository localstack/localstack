package main

import (
	"context"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"os"
	"fmt"
)

func getConfig() *aws.Config {
	shouldConfigure := os.Getenv("CONFIGURE_CLIENT")
	if shouldConfigure == "1" {
	    endpointUrl := os.Getenv("AWS_ENDPOINT_URL")
		return &aws.Config{
			Region:      aws.String("us-east-1"),
			Credentials: credentials.NewStaticCredentials("test", "test", ""),
			Endpoint:    aws.String(endpointUrl),
		}
	}
	return &aws.Config{
		Region:      aws.String("us-east-1"),
		Credentials: credentials.NewStaticCredentials("test", "test", ""),
	}
}

func HandleRequest(context context.Context, event map[string]string) (string, error) {
    // SDK v1: https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/welcome.html
    config := &aws.Config{}
    endpointUrl := os.Getenv("AWS_ENDPOINT_URL")
    if endpointUrl != "" {
        config = &aws.Config{
            Endpoint:    aws.String(endpointUrl),
        }
    }

	sess := session.Must(session.NewSession(config))
	svc := sqs.New(sess)
	input := &sqs.ListQueuesInput{}
	response, err := svc.ListQueues(input)
	if err != nil {
		return "fail", err
	}
    fmt.Printf("response: %+v\n", response)

	return "ok", nil
}

func main() {
	lambda.Start(HandleRequest)
}
