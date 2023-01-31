const AWS = require("aws-sdk");
const shouldConfigureClient = process.env.CONFIGURE_CLIENT === "1";

let sqsClient;

if (shouldConfigureClient) {
    sqsClient = new AWS.SQS({
        region: "us-east-1",
        endpoint: `http://${process.env.LOCALSTACK_HOSTNAME}:${process.env.EDGE_PORT}`
    });
} else {
    sqsClient = new AWS.SQS({region: "us-east-1"});
}

exports.handler = async function(event, context) {
    await sqsClient.listQueues().promise();
    return "ok"
};
