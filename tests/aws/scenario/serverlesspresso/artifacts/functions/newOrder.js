// Source adapted from: https://github.com/aws-samples/serverless-coffee-workshop

'use strict';

const { DynamoDBDocument } = require('@aws-sdk/lib-dynamodb');
const { DynamoDB } = require('@aws-sdk/client-dynamodb');

const documentClient = DynamoDBDocument.from(new DynamoDB())

// Triggered by event: DetailType: "Validator.NewOrder"

exports.handler = async (event) => {
    console.log(JSON.stringify(event, null, 2))

    const result = await documentClient.put({
        TableName: process.env.TableName,
        Item: {
            PK: 'orders',
            SK: event.detail.orderId,
            USERID: event.detail.userId,
            ORDERSTATE: 'CREATED',
            bucketState: event.detail.bucket,
            robot: (event.detail.robot || false),
            TS: Date.now()
        }
    })

    console.log({ result })
}

