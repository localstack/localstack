// Source adapted from: https://github.com/aws-samples/serverless-coffee-workshop

const AWS = require('aws-sdk')
AWS.config.update({region: process.env.AWS_REGION})
const iotdata = new AWS.IotData({ endpoint: process.env.IOT_DATA_ENDPOINT })

// Publishes the message to the IoT topic
const iotPublish = async function (baseTopic, event) {
    const topic = `${baseTopic}${event.detail.userId}`

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
        const result = await iotdata.publish(params).promise()
        console.log('iotPublish successful: ', topic, result)
    } catch (err) {
        console.error('iotPublish error:', err)
    }
}

exports.handler = async (event) => {
    console.log(JSON.stringify(event, null, 2))
    await iotPublish(process.env.IOT_TOPIC, event)
}
