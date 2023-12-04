// source: https://github.com/aws-samples/aws-bookstore-demo-app/blob/master/functions/setup/uploadBooks.js
"use strict";

const https = require("https");
const url = require("url");

var AWS = require("aws-sdk");
let documentClient;
let s3Client;
if (process.env.AWS_ENDPOINT_URL) {
  const localStackS3Config = {
      endpoint: process.env.AWS_ENDPOINT_URL,
      s3ForcePathStyle: true,
      accessKeyId: 'test',
      secretAccessKey: 'test',
      region: 'us-east-1',
  };
  s3Client = new AWS.S3(localStackS3Config);

  documentClient = new AWS.DynamoDB.DocumentClient({
        endpoint: process.env.AWS_ENDPOINT_URL,
        region: 'us-east-1', // Change the region as per your setup
      }
  );
} else {
  // Use the default AWS configuration
  s3Client = new AWS.S3();
  documentClient = new AWS.DynamoDB.DocumentClient();
}

// UploadBooks - Upload sample set of books to DynamoDB
exports.handler = function(event, context, callback) {
    getBooksData().then(function(data) {
      var booksString = data.Body.toString("utf-8");
      console.log("received booksString");
      var booksList = JSON.parse(booksString);
      console.log("parsing bookslist");
      uploadBooksData(booksList);
      console.log("uploaded books");
    }).catch(function(err) {
      console.log(err);
      var responseData = { Error: "Upload books failed" };
      console.log(responseData.Error);
    });

    return;
};
function uploadBooksData(book_items) {
  var items_array = [];
  for (var i in book_items) {
    var book = book_items[i];
    console.log(book.id)
    var item = {
      PutRequest: {
       Item: book
      }
    };
    items_array.push(item);
  }

  // Batch items into arrays of 25 for BatchWriteItem limit
  var split_arrays = [], size = 25;
    while (items_array.length > 0) {
        split_arrays.push(items_array.splice(0, size));
    }

  split_arrays.forEach( function(item_data) {
    putItem(item_data)
  });
}

// Retrieve sample books from aws-bookstore-demo S3 Bucket
function getBooksData() {
  var params = {
    Bucket: process.env.S3_BUCKET, // aws-bookstore-demo
    Key: process.env.FILE_NAME // data/books.json
 };
 return s3Client.getObject(params).promise();
}


function putItem(items_array) {
  var tableName = process.env.TABLE_NAME;
  var params = {
    RequestItems: {
      [tableName]: items_array
    }
  };
  documentClient.batchWrite(params, function(err, data) {
      if (err) console.log(err);
      else console.log(data);
   });
}
