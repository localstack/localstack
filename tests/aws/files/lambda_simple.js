exports.handler = async function(event, context) {
    console.info('EVENT ' + JSON.stringify(event, null, 2));
    return {
        statusCode: 200,
        body: 'I am a %s API!',
    };
}