// Source adapted from: https://github.com/aws-samples/serverless-coffee-workshop

const { EventBridge } = require('@aws-sdk/client-eventbridge');
const eventbridge = new EventBridge()

const { DynamoDBDocument } = require("@aws-sdk/lib-dynamodb");
const { DynamoDB } = require("@aws-sdk/client-dynamodb");

const crypto = require('crypto');
const documentClient = DynamoDBDocument.from(new DynamoDB())

const TIME_INTERVAL = (process.env.TimeInterval * 60 * 1000)

// inlined partial nanoid library
const urlAlphabet = 'useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict'
const POOL_SIZE_MULTIPLIER = 128
let pool, poolOffset

function fillPool(bytes) {
    if (!pool || pool.length < bytes) {
        pool = Buffer.allocUnsafe(bytes * POOL_SIZE_MULTIPLIER)
        crypto.getRandomValues(pool)
        poolOffset = 0
    } else if (poolOffset + bytes > pool.length) {
        crypto.getRandomValues(pool)
        poolOffset = 0
    }
    poolOffset += bytes
}

function nanoid(size = 21) {
    fillPool((size -= 0))
    let id = ''
    for (let i = poolOffset - size; i < poolOffset; i++) {
        id += urlAlphabet[pool[i] & 63]
    }
    return id
}

const getItem = async (id) => {
    const params = {
        TableName: process.env.TableName,
        KeyConditionExpression: "#pk = :pk",
        ExpressionAttributeNames: {
            "#pk": "PK"
        },
        ExpressionAttributeValues: {
            ":pk": id
        }
    }
    console.log('getItem params: ', params)

    try {
        const result = await documentClient.query(params)
        if (!result.Items) {
            result.Items = []
        }
        console.log('getItem result: ', result)
        return result
    } catch (err) {
        console.error('getItem error: ', err)
    }
    return {Items:[]}
}

const saveItem = async (record) => {
    const Item = {
        PK: record.last_id,
        ...record
    }
    console.log(Item)
    const result = await documentClient.put({
        TableName: process.env.TableName,
        Item
    }).promise()
    console.log('saveItem: ', result)
}

const decrementToken = async (record) => {
    const params = {
        TableName: process.env.TableName,
        Key: {
            PK: record.last_id
        },
        UpdateExpression: "set availableTokens = availableTokens - :val",
        ExpressionAttributeValues:{
            ":val": 1
        },
        ReturnValues:"UPDATED_NEW"
    }
    console.log(params)
    const result = await documentClient.update(params)
    console.log('decrementToken: ', result)
}



// Verifies a QR code
exports.handler = async (event,context) => {
    console.log(JSON.stringify(event, null, 2))
    let bucket = {}

    // Missing parameters
    if (!event.queryStringParameters) {
        return {
            statusCode: 422,
            body: JSON.stringify({ error: "Missing parameter" })
        }
    }

    // Load bucket from DynamoDB, if available
    const CURRENT_TIME_BUCKET_ID = parseInt(Date.now() / TIME_INTERVAL)
    console.log('Bucket:', CURRENT_TIME_BUCKET_ID)

    const result = await getItem(CURRENT_TIME_BUCKET_ID)
    if ( result.Items.length != 0 ) {
        bucket = result.Items[0]
        console.log('Bucket loaded: ', bucket)
    } else {
        return {
            statusCode: 400,
            body: JSON.stringify({
                error: 'Invalid code'
            })
        }
    }

    // Validate token
    if (event.queryStringParameters.token != bucket.last_code) {
        return {
            statusCode: 400,
            body: JSON.stringify({
                error: 'Invalid code'
            })
        }
    }

    // Check if enough tokens
    if (bucket.availableTokens < 1) {
        return {
            statusCode: 200,
            body: JSON.stringify({
                error: 'No tokens remaining'
            })
        }
    }

    // Decrement token count
    const orderId = nanoid()
    const userId = event.requestContext.authorizer.claims.sub


    bucket.availableTokens--
    await decrementToken(bucket)

    // Publish to EventBridge with new order ID
    const response = await eventbridge.putEvents({
        Entries: [
            {
                Detail: JSON.stringify({
                    orderId,
                    userId,
                    Message:"A Lambda function is invoked by a POST request to Amazon API Gateway. The Lambda function, Takes the token ID from the QR code scan and checks it against the valid token ID's stored in a DynamoDB database. If Valid, a new Step Functions Workflow is started, this workflow ochestrates various AWS services to move the order along to completion.",
                    bucket
                }),
                DetailType: 'Validator.NewOrder',
                EventBusName: process.env.BusName,

                Source: process.env.Source,
                Resources: [context.invokedFunctionArn],
                Time: new Date
            }
        ]
    })
    console.log('EventBridge putEvents:', response)

    // Return the code
    return {
        statusCode: 200,
        body: JSON.stringify({ orderId }),
        headers: {
            "Access-Control-Allow-Headers" : "Content-Type",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
        },
    }
}
