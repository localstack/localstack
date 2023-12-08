const { DynamoDBClient, DeleteItemCommand } = require("@aws-sdk/client-dynamodb");
const { marshall } = require("@aws-sdk/util-dynamodb");
const { success, failure } = require("./libs/response");

// eslint-disable-next-line no-unused-vars
// In Node.js, you don't need to import types like in TypeScript, so the import for APIGatewayEvent can be removed.

exports.handler = async (event) => {
  const params = {
    TableName: process.env.NOTES_TABLE_NAME || "",
    // 'Key' defines the partition key and sort key of the item to be removed
    // - 'noteId': path parameter
    Key: marshall({ noteId: event.pathParameters?.id }),
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
    await client.send(new DeleteItemCommand(params));
    return success({ status: true });
  } catch (e) {
    console.log(e);
    return failure({ status: false });
  }
};
