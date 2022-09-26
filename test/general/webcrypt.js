const webcrypt = require('nitrokey_webcrypt/dist/webcrypt.min');
const { WEBCRYPT_STATUS, WEBCRYPT_OPENPGP_GENERATE } = webcrypt;

const chai = require('chai');

const { expect } = chai;


// http://localhost:8080/test/unittests.html?grep=Unit%20Tests%20General%20OpenPGP%5C.js%20webcrypt%20public%20api%20tests%20WebCrypt%20general%20%5Cx2d%20unit%20tests%20Status%20test

module.exports = () => describe('OpenPGP.js webcrypt public api tests', function () {

  describe('WebCrypt general - unit tests', function () {

    beforeEach(async function () {
    });

    afterEach(function () {
    });

    it('Status test', async function () {
      const res = await WEBCRYPT_STATUS(console.log);
      expect(res["UNLOCKED"]).to.be.false;
      return true;
    });

  });

});
