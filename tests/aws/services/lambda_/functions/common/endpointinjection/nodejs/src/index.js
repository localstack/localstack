// SDK v2: https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/welcome.html
const AWS = require("aws-sdk");


const sqsClient = new AWS.SQS({
    endpoint: process.env.AWS_ENDPOINT_URL
});

exports.handler = async function(event, context) {
    // NOTE: With older AWS SDKs, SQS responses are broken returning some ResponseMetadata instead of real data.
    const response = await sqsClient.listQueues().promise();
    console.log(response);

    return "ok"
};
