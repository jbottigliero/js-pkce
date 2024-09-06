const crypto = require('crypto');

global.crypto = crypto.webcrypto;
global.btoa = (str) => Buffer.from(str).toString('base64');

require('jest-fetch-mock').enableMocks();
