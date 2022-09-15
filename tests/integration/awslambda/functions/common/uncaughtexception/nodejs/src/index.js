exports.handler = async function(event, context) {
    throw Error(`Error: ${event.error_msg}`)
};
