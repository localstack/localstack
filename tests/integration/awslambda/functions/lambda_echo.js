exports.handler = function(event, context, callback) {
	console.log(event);
	if (callback) {
		callback(null, event);
	} else {
		context.succeed(event);
	}
};
