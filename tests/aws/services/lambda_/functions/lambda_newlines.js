exports.handler = async function(event, context) {
    console.log("test\nwith\nnewlines");
    console.log("test\rwith\rcarriage\rreturns");
    return event;
}
