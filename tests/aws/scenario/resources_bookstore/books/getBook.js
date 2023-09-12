// source adapted from https://github.com/aws-samples/aws-bookstore-demo-app

"use strict";

const AWS = require("aws-sdk");
let dynamoDb;
if (process.env.LOCALSTACK_HOSTNAME) {
  dynamoDb = new AWS.DynamoDB.DocumentClient({
        endpoint: `http://${process.env.LOCALSTACK_HOSTNAME}:${process.env.EDGE_PORT}`,
        region: 'us-east-1', // Change the region as per your setup
      }
  );
} else {
  dynamoDb = new AWS.DynamoDB.DocumentClient();
}
// GetBook - Get book informaton for a given book id
exports.handler = (event, context, callback) => {

  // Return immediately if being called by warmer
  if (event.source === "warmer") {
    return callback(null, "Lambda is warm");
  }

  const params = {
    TableName: process.env.TABLE_NAME, // [ProjectName]-Books
    // 'Key' defines the partition key of the item to be retrieved
    // - 'id': a unique identifier for the book (uuid)
    Key: {
      id: event.pathParameters.id
    }
  };
  dynamoDb.get(params, (error, data) => {
    // Set response headers to enable CORS (Cross-Origin Resource Sharing)
    const headers = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials" : true
    };

    // Return status code 500 on error
    if (error) {
      const response = {
         statusCode: 500,
         headers: headers,
         body: error
      };
      callback(null, response);
      return;
    }

    // Return status code 200 and the retrieved item on success
    const response = {
      statusCode: 200,
      headers: headers,
      body: JSON.stringify(data.Item)
    };
    callback(null, response);
  });
}
