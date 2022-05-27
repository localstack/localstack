exports.handler = function(event, context) {
  console.log("FUNCTION HAS RUN")
  return {
    "isBase64Encoded": false,
    "statusCode": 200,
    "headers": { "content-type": "application/xml"},
    "body": "<message>completed</message>"
}}