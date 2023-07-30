package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

func main() {
	opts := []func(*config.LoadOptions) error{
		config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(func(_, _ string, _ ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				PartitionID:       "aws",
				URL:               "http://localhost:4566",
				SigningRegion:     "us-east-1",
				Source:            aws.EndpointSourceCustom,
				HostnameImmutable: true,
			}, nil
		})),

		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			"test",
			"test",
			"test",
		)),
	}

	cfg, _ := config.LoadDefaultConfig(context.Background(), opts...)

	sqsClient := sqs.NewFromConfig(cfg)
	queueName := "myqueue"

	queue, err := sqsClient.CreateQueue(context.TODO(), &sqs.CreateQueueInput{
		QueueName: &queueName,
	})
	if err != nil {
		panic(err)
	}
	println(*queue.QueueUrl)

	messageBody := "my-message"
	response, err := sqsClient.SendMessage(context.TODO(), &sqs.SendMessageInput{
		QueueUrl:    queue.QueueUrl,
		MessageBody: &messageBody,
	})

	if err != nil {
		panic(err)
	}
	println(*response.MessageId)
}
