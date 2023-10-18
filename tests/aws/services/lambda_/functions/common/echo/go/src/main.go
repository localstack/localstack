package main

import (
	"context"
	"github.com/aws/aws-lambda-go/lambda"
)

func HandleRequest(ctx context.Context, event any) (any, error) {
	return event, nil
}

func main() {
	lambda.Start(HandleRequest)
}
