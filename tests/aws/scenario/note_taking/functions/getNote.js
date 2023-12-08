const { DynamoDBClient, GetItemCommand } = require("@aws-sdk/client-dynamodb");
const { marshall, unmarshall } = require("@aws-sdk/util-dynamodb");
const { success, failure, not_found } = require("./libs/response");

// eslint-disable-next-line no-unused-vars
// In Node.js, you don't need to import types like in TypeScript, so the import for APIGatewayEvent can be removed.

exports.handler = async (event) => {
  const params = {
    TableName: process.env.NOTES_TABLE_NAME || "",
    // 'Key' defines the partition key and sort key of the item to be retrieved
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
    const result = await client.send(new GetItemCommand(params));
    if (result.Item) {
      // Return the retrieved item
      return success(unmarshall(result.Item));
    } else {
      return not_found({ status: false, error: "Item not found." });
    }
  } catch (e) {
    console.log(e);
    return failure({ status: false });
  }
};
