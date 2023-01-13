package main

import (
	"context"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"os"
)

func getConfig() *aws.Config {
	shouldConfigure := os.Getenv("CONFIGURE_CLIENT")
	if shouldConfigure == "1" {
	    endpointUrl := "http://" + os.Getenv("LOCALSTACK_HOSTNAME") + ":" + os.Getenv("EDGE_PORT")
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
	sess := session.Must(session.NewSession(getConfig()))
	svc := sqs.New(sess)
	input := &sqs.ListQueuesInput{}
	_, err := svc.ListQueues(input)
	if err != nil {
		return "fail", err
	}

	return "ok", nil
}

func main() {
	lambda.Start(HandleRequest)
}
