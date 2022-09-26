/* eslint-disable max-lines */
// eslint-disable-next-line no-unused-vars
/* globals tryTests: true */

// import { WEBCRYPT_STATUS, WEBCRYPT_OPENPGP_GENERATE } from 'nitrokey_webcrypt';
const { WEBCRYPT_STATUS, WEBCRYPT_OPENPGP_GENERATE } = require('nitrokey_webcrypt');
// import * as webcrypt from 'nitrokey_webcrypt';

// window.webcrypt = webcrypt;
// const { WEBCRYPT_STATUS, WEBCRYPT_OPENPGP_GENERATE } = require('nitrokey_webcrypt');

// const util = require('../../src/util');

// import { WEBCRYPT_OPENPGP_GENERATE } from '../../../webcrypt-js-lib/js/webcrypt';
// import * as webcrypt from 'nitrokey_webcrypt';

// const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

module.exports = () => describe('OpenPGP.js webcrypt public api tests', function () {

  describe('webcrypt WebCrypt decrypt - unit tests', function () {

    beforeEach(async function () {
    });

    afterEach(function () {
    });

    it('test test', async function () {
      // eslint-disable-next-line new-cap
      // await WEBCRYPT_STATUS(console.log);
      // eslint-disable-next-line new-cap
      await WEBCRYPT_STATUS(console.log);
      // eslint-disable-next-line new-cap
      // await WEBCRYPT_OPENPGP_GENERATE(console.log);
      return true;
    });


  });

});
