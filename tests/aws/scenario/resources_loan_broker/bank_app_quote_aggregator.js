const { DynamoDBClient, UpdateItemCommand } = require("@aws-sdk/client-dynamodb");
const { unmarshall } = require("@aws-sdk/util-dynamodb");
const { SFNClient, SendTaskSuccessCommand } = require("@aws-sdk/client-sfn");

//const dynamodb = new DynamoDBClient({ apiVersion: "2012-08-10" });
//const sfn = new SFNClient();

let sfn;
let dynamodb;
if (process.env.LOCALSTACK_HOSTNAME) {
  const localStackConfig = {
    endpoint: `http://${process.env.LOCALSTACK_HOSTNAME}:${process.env.EDGE_PORT}`,
    region: 'us-east-1', // Change the region as per your setup
    apiVersion: "2012-08-10"
  };
  dynamodb = new  DynamoDBClient(localStackConfig);
  sfn = new SFNClient(localStackConfig)
} else {
  // Use the default AWS configuration
  dynamodb = new DynamoDBClient({apiVersion: "2012-08-10"});
  sfn = new SFNClient();
}

const mortgageQuotesTable = process.env.MORTGAGE_QUOTES_TABLE;


const quoteRequestComplete = (amountQuotes) =>
    amountQuotes >= 2;


const createAppendQuoteUpdateItemCommand = (tableName, id, quote) =>
    new UpdateItemCommand({
        TableName: tableName,
        Key: { Id: { S: id } },
        UpdateExpression: "SET #quotes = list_append(if_not_exists(#quotes, :empty_list), :quote)",
        ExpressionAttributeNames: {
            "#quotes": "quotes",
        },
        ExpressionAttributeValues: {
            ":quote": {
                L: [
                    {
                        M: {
                            bankId: { S: quote["bankId"] },
                            rate: { N: quote["rate"].toString() },
                        },
                    },
                ],
            },
            ":empty_list": { L: [] },
        },
        ReturnValues: "ALL_NEW",
    });


exports.handler = async (event) => {
    console.log("Received event:", JSON.stringify(event));
    console.log("Processing %d records", event["Records"].length);

    var persistedMortgageQuotes;
    for (record of event["Records"]) {
        console.log(record);

        var quote = JSON.parse(record["body"]);
        console.log("Persisting quote: %s", JSON.stringify(quote));

        var id = quote["id"];
        var taskToken = quote["taskToken"];

        var appendQuoteUpdateItemCommand = createAppendQuoteUpdateItemCommand(mortgageQuotesTable, id, quote);

        var dynamodbResponse = await dynamodb.send(appendQuoteUpdateItemCommand);
        console.log(JSON.stringify(dynamodbResponse));
        console.log(unmarshall(dynamodbResponse.Attributes));
        persistedMortgageQuotes = unmarshall(dynamodbResponse.Attributes);
    }

    console.log("Persisted %d quotes", persistedMortgageQuotes.quotes.length);

    if (quoteRequestComplete(persistedMortgageQuotes.quotes.length)) {
        console.log("Enough quotes are available");
        var sendTaskSuccessCommand = new SendTaskSuccessCommand({
            taskToken,
            output: JSON.stringify(persistedMortgageQuotes.quotes),
        });

        try {
            var response = await sfn.send(sendTaskSuccessCommand);
            console.log(response);
        } catch (error) {
            console.log(error);
        }
    } else {
        console.log("Not enough quotes available yet");
    }
};
