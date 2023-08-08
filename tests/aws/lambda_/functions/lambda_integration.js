exports.handler = function(event, context, callback) {
	console.log('Node.js Lambda handler executing.');
	var result = {context};
	if (callback) {
		callback(null, result);
	} else {
		context.succeed(result);
	}
};
