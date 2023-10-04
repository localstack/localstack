const { DynamoDBClient, ScanCommand } = require("@aws-sdk/client-dynamodb");
const { unmarshall } = require("@aws-sdk/util-dynamodb");

const { success, failure } = require("./libs/response");

exports.handler = async () => {
  const params = {
    TableName: process.env.NOTES_TABLE_NAME || "",
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
    const result = await client.send(new ScanCommand(params));
    // Return the matching list of items in response body
    return success(result.Items.map((Item) => unmarshall(Item)));
  } catch (e) {
    console.log(e);
    return failure({ status: false });
  }
};
