exports.handler = async function (event, context) {
  console.log("FUNCTION HAS RUN")
  return {
    isBase64Encoded: false,
    statusCode: 300,
    headers: { "content-type": "application/xml" },
    body: "<message>completed</message>"
  }
}
