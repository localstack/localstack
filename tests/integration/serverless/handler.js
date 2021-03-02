module.exports.test = function(event) {
  console.log('!!!test', JSON.stringify(event));
};

module.exports.processKinesis = function(event) {
  console.log('!!!processKinesis', JSON.stringify(event));
};
