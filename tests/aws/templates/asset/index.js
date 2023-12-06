'use strict';

async function handler() {
  return 'Hi Localstack';
}

module.exports = {
  createUserHandler: handler,
  authenticateUserHandler: handler
};
