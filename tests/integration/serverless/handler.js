module.exports.test = function(event) {
  console.log('!!!test', JSON.stringify(event));
};

module.exports.tests = function(event) {
  console.log('!!!tests', JSON.stringify(event));
};

module.exports.processKinesis = function(event) {
  console.log('!!!processKinesis', JSON.stringify(event));
};

module.exports.createQueue = function(event) {
  console.log('!!!createQueue', JSON.stringify(event));
};

module.exports.createHttpRouter = function(event) {
  console.log('!!!createHttpRouter', JSON.stringify(event));
};
