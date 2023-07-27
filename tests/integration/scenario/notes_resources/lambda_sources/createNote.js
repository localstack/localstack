const crypto = require("crypto");
const { DynamoDBClient, PutItemCommand } = require("@aws-sdk/client-dynamodb");
const { marshall, unmarshall } = require("@aws-sdk/util-dynamodb");
const { success, failure } = require("./libs/response");

// eslint-disable-next-line no-unused-vars
// In Node.js, you don't need to import types like in TypeScript, so the import for APIGatewayEvent can be removed.

exports.handler = async (event) => {
  const data = JSON.parse(event.body || "{}");
  const params = {
    TableName: process.env.NOTES_TABLE_NAME || "",
    Item: marshall({
      noteId: crypto.randomBytes(20).toString("hex"),
      content: data.content,
      createdAt: Date.now().toString(),
      ...(data.attachment && { attachment: data.attachment }),
    }),
  };


  try {
    let client;
    if (process.env.LOCALSTACK_HOSTNAME) {
      const localStackConfig = {
        endpoint: `http://${process.env.LOCALSTACK_HOSTNAME}:${process.env.EDGE_PORT}`,
        region: 'us-east-1', // Change the region as per your setup
      };
      client = new  DynamoDBClient(localStackConfig);
    } else {
      // Use the default AWS configuration
      client = new DynamoDBClient({});
    }
    await client.send(new PutItemCommand(params));
    return success(unmarshall(params.Item));
  } catch (e) {
    console.log(e);
    return failure({ status: false });
  }
};
