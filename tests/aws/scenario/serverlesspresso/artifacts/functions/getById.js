// Source adapted from: https://github.com/aws-samples/serverless-coffee-workshop

'use strict'

const AWS = require('aws-sdk')
AWS.config.update({ region: process.env.AWS_REGION })
const stepFunctions = new AWS.StepFunctions()
const documentClient = new AWS.DynamoDB.DocumentClient()

// Update order
const getOrder = async (record) => {
    const params = {
        TableName: process.env.TableName,
        Key: {
            PK: 'orders',
            SK: record.orderId,
        }
    }
    // console.log(params)
    const result = await documentClient.get(params).promise()
    // console.log(result)

    return {
        orderId: record.orderId,
        drinkOrder: result.Item.drinkOrder,
        orderState: result.Item.ORDERSTATE,
        TS: result.TS
    }
}

// Returns list of open orders, sorted by time
exports.handler = async (event) => {
    console.log(JSON.stringify(event, null, 2))

    const record = {
        orderId: event.pathParameters.id,
        userId: event.requestContext.authorizer.jwt.claims.sub
    }

    const result = await getOrder(record)

    return {
        "statusCode": 200,
        "body": JSON.stringify({ result }),
        "isBase64Encoded": false
    }
}
