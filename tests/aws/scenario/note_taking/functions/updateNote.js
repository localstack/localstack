const { DynamoDBClient, UpdateItemCommand } = require("@aws-sdk/client-dynamodb");
const { marshall } = require("@aws-sdk/util-dynamodb");
const { success, failure } = require("./libs/response");

// eslint-disable-next-line no-unused-vars
// In Node.js, you don't need to import types like in TypeScript, so the import for APIGatewayEvent can be removed.

exports.handler = async (event) => {
  const data = JSON.parse(event.body || "{}");
  const params = {
    TableName: process.env.NOTES_TABLE_NAME || "",
    // 'Key' defines the partition key and sort key of the item to be updated
    // - 'noteId': path parameter
    Key: marshall({ noteId: event.pathParameters?.id }),
    // 'UpdateExpression' defines the attributes to be updated
    // 'ExpressionAttributeValues' defines the value in the update expression
    UpdateExpression: "SET content = :content",
    ExpressionAttributeValues: marshall({ ":content": data.content }),
    // 'ReturnValues' specifies if and how to return the item's attributes,
    // where ALL_NEW returns all attributes of the item after the update; you
    // can inspect 'result' below to see how it works with different settings
    ReturnValues: "ALL_NEW",
  };

  try {
    let client;
    if (process.env.AWS_ENDPOINT_URL) {
      const localStackConfig = {
        endpoint: process.env.AWS_ENDPOINT_URL,
        region: process.env.AWS_REGION || "us-east-1",
      };
      client = new  DynamoDBClient(localStackConfig);
    } else {
      // Use the default AWS configuration
      client = new DynamoDBClient({});
    }
    await client.send(new UpdateItemCommand(params));
    return success({ status: true });
  } catch (e) {
    console.log(e);
    return failure({ status: false });
  }
};
