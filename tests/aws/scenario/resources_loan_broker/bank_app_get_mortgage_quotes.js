const { DynamoDBClient, GetItemCommand } = require("@aws-sdk/client-dynamodb");
const { unmarshall } = require("@aws-sdk/util-dynamodb");

let dynamodb;
if (process.env.LOCALSTACK_HOSTNAME) {
  const localStackConfig = {
    endpoint: `http://${process.env.LOCALSTACK_HOSTNAME}:${process.env.EDGE_PORT}`,
    region: 'us-east-1', // Change the region as per your setup
    apiVersion: "2012-08-10"
  };
  dynamodb = new  DynamoDBClient(localStackConfig);
} else {
  // Use the default AWS configuration
  dynamodb = new DynamoDBClient({apiVersion: "2012-08-10"});
}
//const dynamodb = new DynamoDBClient({ apiVersion: "2012-08-10" });

const mortgageQuotesTable = process.env.MORTGAGE_QUOTES_TABLE;

exports.handler = async (event) => {
    console.log("Received event:", JSON.stringify(event));
    var id = event["Id"];

    var getItemCommand = new GetItemCommand({
        TableName: mortgageQuotesTable,
        Key: { Id: { S: id } },
    });

    var getItemResponse = await dynamodb.send(getItemCommand);
    console.debug(JSON.stringify(getItemResponse));

    if (getItemResponse.Item) {
        console.debug(unmarshall(getItemResponse.Item));

        return unmarshall(getItemResponse.Item);
    } else {
        return { quotes: [] };
    }
};
