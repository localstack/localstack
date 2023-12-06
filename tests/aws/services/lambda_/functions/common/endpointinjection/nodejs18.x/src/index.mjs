// SDK v3: https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/welcome.html
import {SQSClient, ListQueuesCommand} from "@aws-sdk/client-sqs";


const sqsClient = new SQSClient({
    endpoint: process.env.AWS_ENDPOINT_URL
});

export const handler = async(event) => {
    const cmd = new ListQueuesCommand({});
    const response = await sqsClient.send(cmd);
    console.log(response);

    return "ok"
};
