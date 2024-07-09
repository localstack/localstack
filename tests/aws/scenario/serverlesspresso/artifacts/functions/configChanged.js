// Source adapted from: https://github.com/aws-samples/serverless-coffee-workshop
'use strict'

const { DynamoDBDocument } = require('@aws-sdk/lib-dynamodb');
const { DynamoDB } = require('@aws-sdk/client-dynamodb');
const { EventBridge } = require('@aws-sdk/client-eventbridge');

const documentClient = DynamoDBDocument.from(new DynamoDB())
const eventbridge = new EventBridge()

// Returns application config
exports.handler = async (event) => {
    console.log(JSON.stringify(event, null, 0))
    const NewImage = event.Records[0].dynamodb.NewImage

    // Publish to EventBridge with change info
    const params = {
        Entries: [
            {
                Detail: JSON.stringify({ NewImage }),
                DetailType: 'ConfigService.ConfigChanged',
                EventBusName: process.env.EventBusName,
                Source: process.env.Source,
                Time: new Date
            }
        ]
    }

    console.log('Event: ', JSON.stringify(params, null, 0))
    const response = await eventbridge.putEvents(params)
    console.log('EventBridge putEvents:', response)
}

