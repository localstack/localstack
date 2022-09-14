package main

import (
	"context"
	"errors"
	"github.com/aws/aws-lambda-go/lambda"
)

func HandleRequest(context context.Context, event map[string]string) (map[string]string, error) {

	return nil, errors.New("Error: " + event["error_msg"])
}

func main() {
	lambda.Start(HandleRequest)
}
