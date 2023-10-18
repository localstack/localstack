const success = (body) => {
  return buildResponse(200, body);
};

const failure = (body) => {
  return buildResponse(500, body);
};

const not_found = (body) => {
  return buildResponse(404, body);
};

const buildResponse = (statusCode, body) => ({
  statusCode: statusCode,
  headers: {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Credentials": true,
  },
  body: JSON.stringify(body),
});

module.exports = { success, failure, not_found };
