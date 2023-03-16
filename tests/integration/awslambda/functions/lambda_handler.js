exports.handler = async (event, context, callback) => {
   context.getRemainingTimeInMillis();
   if (callback) {
    callback();
   }
   console.log(JSON.stringify(event))
   return {
     statusCode: 200,
     body: JSON.stringify(`response from localstack lambda: ${JSON.stringify(event)}`),
     isBase64Encoded: false,
     headers: {}
   }
}
