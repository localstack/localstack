// Source adapted from: https://github.com/aws-samples/serverless-coffee-workshop

const { DynamoDBDocument } = require("@aws-sdk/lib-dynamodb");
const { DynamoDB } = require("@aws-sdk/client-dynamodb");

const documentClient = DynamoDBDocument.from(new DynamoDB())

const TIME_INTERVAL = (process.env.TimeInterval * 60 * 1000)
const NANO_ID_CODE_LENGTH = process.env.CodeLength
const AVAILABLE_TOKENS = process.env.TokensPerBucket

// inlined partial nanoid library
const urlAlphabet = 'useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict'
const POOL_SIZE_MULTIPLIER = 128
let pool, poolOffset

const crypto = require('crypto');
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
        console.log('getItem result: ', result)
        return result
    } catch (err) {
        console.error('getItem error: ', err)
    }
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
    })
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


const isAdmin = (requestContext) => {
    try {
        const groups = requestContext.authorizer.claims['cognito:groups'].replace('[','').replace(']','').split(',')
        return groups.includes('admin')
    } catch (err) {
        return false
    }
}

// Returns details of a Place ID where the app has user-generated content.
exports.handler = async (event) => {
    console.log(JSON.stringify(event, null, 0))

    // If not an admin user, exit
    if (!isAdmin(event.requestContext)) {
        return {
            "statusCode": 403
        }
    }

    let bucket = {}
    const CURRENT_TIME_BUCKET_ID = parseInt(Date.now() / TIME_INTERVAL)
    console.log('Bucket:', CURRENT_TIME_BUCKET_ID, )

    // Load bucket from DynamoDB, if available
    const result = await getItem(CURRENT_TIME_BUCKET_ID)
    if ( result.Items.length != 0 ) {
        bucket = result.Items[0]
        console.log('Bucket loaded: ', bucket)
    } else {

        // No bucket info available - create new
        bucket.last_id = CURRENT_TIME_BUCKET_ID
        bucket.last_code = nanoid(NANO_ID_CODE_LENGTH)
        bucket.start_ts = ( TIME_INTERVAL * CURRENT_TIME_BUCKET_ID )
        bucket.start_full = new Date(bucket.start_ts).toString()
        bucket.end_ts = ( TIME_INTERVAL * CURRENT_TIME_BUCKET_ID ) + ( TIME_INTERVAL - 1 )
        bucket.end_full = new Date(bucket.end_ts).toString()
        bucket.availableTokens = parseInt(AVAILABLE_TOKENS)

        // Save to DDB
        console.log('New code: ', { bucket })
        await saveItem(bucket)
    }

    // Return the code
    return {
        statusCode: 200,
        body: JSON.stringify({bucket}),
        headers: {
            "Access-Control-Allow-Headers" : "*",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
        },
    }
}
