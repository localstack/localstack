exports.handler = function(event, context, callback) {
	console.log('Node.js Lambda handler executing.');
	var result = {};
	if(callback) {
		callback(result);
	} else {
		context.succeed(result);
	}
};
