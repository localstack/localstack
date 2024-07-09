// Source adapted from: https://github.com/aws-samples/serverless-coffee-workshop

const { IoTDataPlane } = require('@aws-sdk/client-iot-data-plane');

const iotdata = new IoTDataPlane({
    endpoint: "https://" + process.env.IOT_DATA_ENDPOINT,
    region: process.env.AWS_REGION
})

// Publishes the message to the IoT topic
const iotPublish = async function (topic, event) {
    try {
        const params = {
            topic,
            qos: 1,
            payload: JSON.stringify({
                type: event['detail-type'],
                detail: event.detail
            })
        }
        console.log('Params: ', params)
        const result = await iotdata.publish(params)
        console.log('iotPublish success: ', topic, process.env.IOT_DATA_ENDPOINT, result)
    } catch (err) {
        console.error('iotPublish error:', err)
    }
}

exports.handler = async (event) => {
    console.log(JSON.stringify(event, null, 2))
    await iotPublish(process.env.IOT_TOPIC, event)
}

