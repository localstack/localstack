// Source adapted from: https://github.com/aws-samples/serverless-coffee-workshop

const { DynamoDBDocument } = require("@aws-sdk/lib-dynamodb");
const { DynamoDB } = require("@aws-sdk/client-dynamodb");

const documentClient = DynamoDBDocument.from(new DynamoDB())

// Returns details of a Place ID where the app has user-generated content.
exports.handler = async (event) => {
    console.log(JSON.stringify(event, null, 2))

    const params ={
        TableName: process.env.TableName,
        Item: {
            PK: 'orders',
            SK: event.detail.orderId,
            USERID: event.detail.userId,
            ORDERSTATE: 'CREATED',
            TaskToken: event.detail.TaskToken,
            robot: (event.detail.robot || false),
            TS: Date.now()
        }
    }

    console.log(params)
    const result = await documentClient.put(params)
}
