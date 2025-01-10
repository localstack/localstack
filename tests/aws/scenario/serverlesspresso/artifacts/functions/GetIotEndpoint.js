// Source adapted from: https://github.com/aws-samples/serverless-coffee-workshop

const { IoT } = require("@aws-sdk/client-iot");

exports.handler = function (event, context) {
    console.log("REQUEST RECEIVED:\n" + JSON.stringify(event))

    // For Delete requests, immediately send a SUCCESS response.
    if (event.RequestType == "Delete") {
        sendResponse(event, context, "SUCCESS")
        return
    }

    const iot = new IoT()
    iot.describeEndpoint({ endpointType: "iot:Data-ATS" }, (err, data) => {
        let responseData, responseStatus
        if (err) {
            responseStatus = "FAILED"
            responseData = { Error: "describeEndpoint call failed" }
            console.log(responseData.Error + ":\n", err)
        } else {
            responseStatus = "SUCCESS"
            responseData = { IotEndpointAddress: data.endpointAddress }
            console.log("response data: " + JSON.stringify(responseData))
        }

        sendResponse(event, context, responseStatus, responseData)
    })
}

// Send response to the pre-signed S3 URL
function sendResponse(event, context, responseStatus, responseData) {
    let responseBody = JSON.stringify({
        Status: responseStatus,
        Reason: `CloudWatch Log Stream: ${context.logStreamName}`,
        PhysicalResourceId: context.logStreamName,
        StackId: event.StackId,
        RequestId: event.RequestId,
        LogicalResourceId: event.LogicalResourceId,
        Data: responseData,
    })

    console.log("RESPONSE BODY:\n", responseBody)

    const https = require("https")
    const url = require("url")

    let parsedUrl = url.parse(event.ResponseURL)
    let options = {
        hostname: parsedUrl.hostname,
        port: 443,
        path: parsedUrl.path,
        method: "PUT",
        headers: {
            "content-type": "",
            "content-length": responseBody.length,
        },
    }

    console.log("SENDING RESPONSE...\n")

    const request = https.request(options, function (response) {
        console.log("STATUS: " + response.statusCode)
        console.log("HEADERS: " + JSON.stringify(response.headers))
        // Tell AWS Lambda that the function execution is done
        context.done()
    })

    request.on("error", function (error) {
        console.log("sendResponse Error:" + error)
        // Tell AWS Lambda that the function execution is done
        context.done()
    })

    // write data to request body
    request.write(responseBody)
    request.end()
}

