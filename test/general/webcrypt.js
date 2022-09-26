/* eslint-disable max-lines */
// eslint-disable-next-line no-unused-vars
/* globals tryTests: true */

import * as openpgpjs from '/dist/openpgp'
// const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
// const crypto = require('../../src/crypto');
// const random = require('../../src/crypto/random');
// const util = require('../../src/util');
// const keyIDType = require('../../src/type/keyid');
// const { isAEADSupported } = require('../../src/key');

// const stream = require('@openpgp/web-stream-tools');
// const spy = require('sinon/lib/sinon/spy');


// const detectNode = () => typeof globalThis.process === 'object' && typeof globalThis.process.versions === 'object';

module.exports = () => describe('OpenPGP.js public api tests', function () {

  describe('WebCrypt decrypt - unit tests', function () {
    // let minRSABitsVal;

    beforeEach(async function () {
      // minRSABitsVal = openpgp.config.minRSABits;
      // openpgp.config.minRSABits = 512;
    });

    afterEach(function () {
      // openpgp.config.minRSABits = minRSABitsVal;
    });

    it('test test', async function () {
      await expect(1).should.equal(1);
    });

    /*
    it('Calling decrypt with encrypted key leads to exception', async function () {
      const publicKey = await openpgp.readKey({ armoredKey: pub_key });
      const privateKey = await openpgp.readKey({ armoredKey: priv_key });

      const encOpt = {
        message: await openpgp.createMessage({ text: plaintext }),
        encryptionKeys: publicKey
      };
      const decOpt = {
        decryptionKeys: privateKey
      };
      const encrypted = await openpgp.encrypt(encOpt);
      decOpt.message = await openpgp.readMessage({ armoredMessage: encrypted });
      await expect(openpgp.decrypt(decOpt)).to.be.rejectedWith('Error decrypting message: Decryption key is not decrypted.');
    });

    it('decrypt/verify should succeed with valid signature  (expectSigned=true)', async function () {
      const publicKey = await openpgp.readKey({ armoredKey: pub_key });
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });

      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: plaintext }),
        signingKeys: privateKey,
        encryptionKeys: publicKey
      });
      const { data, signatures } = await openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: encrypted }),
        decryptionKeys: privateKey,
        verificationKeys: publicKey,
        expectSigned: true
      });
      expect(data).to.equal(plaintext);
      expect(await signatures[0].verified).to.be.true;
    });
*/

    /*

    it('decrypt/verify should throw on missing public keys (expectSigned=true)', async function () {
      const publicKey = await openpgp.readKey({ armoredKey: pub_key });
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });

      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: plaintext }),
        encryptionKeys: publicKey,
        signingKeys: privateKey
      });
      await expect(openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: encrypted }),
        decryptionKeys: privateKey,
        expectSigned: true
      })).to.be.eventually.rejectedWith(/Verification keys are required/);
    });

    it('decrypt/verify should throw on missing signature (expectSigned=true)', async function () {
      const publicKey = await openpgp.readKey({ armoredKey: pub_key });
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });

      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: plaintext }),
        encryptionKeys: publicKey
      });
      await expect(openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: encrypted }),
        decryptionKeys: privateKey,
        verificationKeys: publicKey,
        expectSigned: true
      })).to.be.eventually.rejectedWith(/Message is not signed/);
    });

    it('decrypt/verify should throw on invalid signature (expectSigned=true)', async function () {
      const publicKey = await openpgp.readKey({ armoredKey: pub_key });
      const wrongPublicKey = (await openpgp.readKey({ armoredKey: priv_key_2000_2008 })).toPublic();
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });

      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: plaintext }),
        encryptionKeys: publicKey,
        signingKeys: privateKey
      });
      await expect(openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: encrypted }),
        decryptionKeys: privateKey,
        verificationKeys: wrongPublicKey,
        expectSigned: true
      })).to.be.eventually.rejectedWith(/Could not find signing key/);
    });

    it('decrypt/verify should succeed with valid signature (expectSigned=true, with streaming)', async function () {
      const publicKey = await openpgp.readKey({ armoredKey: pub_key });
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });

      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: plaintext }),
        signingKeys: privateKey,
        encryptionKeys: publicKey
      });
      const { data: streamedData, signatures } = await openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: stream.toStream(encrypted) }),
        decryptionKeys: privateKey,
        verificationKeys: publicKey,
        expectSigned: true
      });
      const data = await stream.readToEnd(streamedData);
      expect(data).to.equal(plaintext);
      expect(await signatures[0].verified).to.be.true;
    });

    it('decrypt/verify should throw on missing public keys (expectSigned=true, with streaming)', async function () {
      const publicKey = await openpgp.readKey({ armoredKey: pub_key });
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });

      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: plaintext }),
        encryptionKeys: publicKey,
        signingKeys: privateKey
      });
      await expect(openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: stream.toStream(encrypted) }),
        decryptionKeys: privateKey,
        expectSigned: true
      })).to.be.eventually.rejectedWith(/Verification keys are required/);
    });

    it('decrypt/verify should throw on missing signature (expectSigned=true, with streaming)', async function () {
      const publicKey = await openpgp.readKey({ armoredKey: pub_key });
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });

      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: plaintext }),
        encryptionKeys: publicKey
      });
      await expect(openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: stream.toStream(encrypted) }),
        decryptionKeys: privateKey,
        verificationKeys: publicKey,
        expectSigned: true
      })).to.be.eventually.rejectedWith(/Message is not signed/);
    });

    it('decrypt/verify should throw on invalid signature (expectSigned=true, with streaming)', async function () {
      const publicKey = await openpgp.readKey({ armoredKey: pub_key });
      const wrongPublicKey = (await openpgp.readKey({ armoredKey: priv_key_2000_2008 })).toPublic();
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });

      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: plaintext }),
        encryptionKeys: publicKey,
        signingKeys: privateKey
      });
      const { data: streamedData } = await openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: stream.toStream(encrypted) }),
        decryptionKeys: privateKey,
        verificationKeys: wrongPublicKey,
        expectSigned: true
      });
      await expect(
        stream.readToEnd(streamedData)
      ).to.be.eventually.rejectedWith(/Could not find signing key/);
    });

    it('Supports decrypting with GnuPG dummy key', async function () {
      const { rejectMessageHashAlgorithms } = openpgp.config;
      Object.assign(openpgp.config, { rejectMessageHashAlgorithms: new Set([openpgp.enums.hash.md5, openpgp.enums.hash.ripemd]) });
      try {
        const armoredMessage = `-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.11 (GNU/Linux)

hQEOA1N4OCSSjECBEAP/diDJCQn4e88193PgqhbfAkohk9RQ0v0MPnXpJbCRTHKO
8r9nxiAr/TQv4ZOingXdAp2JZEoE9pXxZ3r1UWew04czxmgJ8FP1ztZYWVFAWFVi
Tj930TBD7L1fY/MD4fK6xjEG7z5GT8k4tn4mLm/PpWMbarIglfMopTy1M/py2cID
/2Sj7Ikh3UFiG+zm4sViYc5roNbMy8ixeoKixxi99Mx8INa2cxNfqbabjblFyc0Z
BwmbIc+ZiY2meRNI5y/tk0gRD7hT84IXGGl6/mH00bsX/kkWdKGeTvz8s5G8RDHa
Za4HgLbXItkX/QarvRS9kvkD01ujHfj+1ZvgmOBttNfP0p8BQLIICqvg1eYD9aPB
+GtOZ2F3+k5VyBL5yIn/s65SBjNO8Fqs3aL0x+p7s1cfUzx8J8a8nWpqq/qIQIqg
ZJH6MZRKuQwscwH6NWgsSVwcnVCAXnYOpbHxFQ+j7RbF/+uiuqU+DFH/Rd5pik8b
0Dqnp0yfefrkjQ0nuvubgB6Rv89mHpnvuJfFJRInpg4lrHwLvRwdpN2HDozFHcKK
aOU=
=4iGt
-----END PGP MESSAGE-----`;
        const passphrase = 'abcd';
        // exercises the GnuPG s2k type 1001 extension:
        // the secrets on the primary key have been stripped.
        const dummyKey = await openpgp.readKey({ armoredKey: armoredDummyPrivateKey1 });
        const publicKey = await openpgp.readKey({ armoredKey: armoredPublicKey1 });
        const message = await openpgp.readMessage({ armoredMessage });
        const primaryKeyPacket = dummyKey.keyPacket.write();
        expect(dummyKey.isDecrypted()).to.be.false;
        const decryptedDummyKey = await openpgp.decryptKey({ privateKey: dummyKey, passphrase });
        expect(decryptedDummyKey.isDecrypted()).to.be.true;
        // decrypting with a secret subkey works
        const msg = await openpgp.decrypt({
          message,
          decryptionKeys: decryptedDummyKey,
          verificationKeys: publicKey,
          config: { rejectPublicKeyAlgorithms: new Set() }
        });
        expect(msg.signatures).to.exist;
        expect(msg.signatures).to.have.length(1);
        expect(await msg.signatures[0].verified).to.be.true;
        expect((await msg.signatures[0].signature).packets.length).to.equal(1);
        // secret key operations involving the primary key should fail
        await expect(openpgp.sign({
          message: await openpgp.createMessage({ text: 'test' }),
          signingKeys: decryptedDummyKey,
          config: { rejectPublicKeyAlgorithms: new Set() }
        })).to.eventually.be.rejectedWith(/Cannot sign with a gnu-dummy key/);
        await expect(
          openpgp.reformatKey({ userIDs: { name: 'test' }, privateKey: decryptedDummyKey })
        ).to.eventually.be.rejectedWith(/Cannot reformat a gnu-dummy primary key/);

        const encryptedDummyKey = await openpgp.encryptKey({ privateKey: decryptedDummyKey, passphrase });
        expect(encryptedDummyKey.isDecrypted()).to.be.false;
        const primaryKeyPacket2 = encryptedDummyKey.keyPacket.write();
        expect(primaryKeyPacket).to.deep.equal(primaryKeyPacket2);
      } finally {
        Object.assign(openpgp.config, { rejectMessageHashAlgorithms });
      }
    });

    it('decrypt with `config.constantTimePKCS1Decryption` option should succeed', async function () {
      const publicKey = await openpgp.readKey({ armoredKey: pub_key });
      const publicKey2 = await openpgp.readKey({ armoredKey: eccPrivateKey });
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });

      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: plaintext }),
        signingKeys: privateKey,
        encryptionKeys: [publicKey, publicKey2]
      });
      const { data } = await openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: encrypted }),
        decryptionKeys: privateKey,
        config: { constantTimePKCS1Decryption: true }
      });
      expect(data).to.equal(plaintext);
    });

    it('decrypt with `config.constantTimePKCS1Decryption` option should succeed (with streaming)', async function () {
      const publicKey = await openpgp.readKey({ armoredKey: pub_key });
      const publicKey2 = await openpgp.readKey({ armoredKey: eccPrivateKey });
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });

      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: plaintext }),
        signingKeys: privateKey,
        encryptionKeys: [publicKey, publicKey2]
      });
      const { data: streamedData } = await openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: stream.toStream(encrypted) }),
        decryptionKeys: privateKey,
        verificationKeys: publicKey,
        expectSigned: true,
        config: { constantTimePKCS1Decryption: true }
      });
      const data = await stream.readToEnd(streamedData);
      expect(data).to.equal(plaintext);
    });

    it('decrypt with `config.constantTimePKCS1Decryption` option should fail if session key algo support is disabled', async function () {
      const publicKeyRSA = await openpgp.readKey({ armoredKey: pub_key });
      const privateKeyRSA = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });
      const privateKeyECC = await openpgp.readPrivateKey({ armoredKey: eccPrivateKey });

      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: plaintext }),
        signingKeys: privateKeyRSA,
        encryptionKeys: [publicKeyRSA, privateKeyECC]
      });

      const config = {
        constantTimePKCS1Decryption: true,
        constantTimePKCS1DecryptionSupportedSymmetricAlgorithms: new Set()
      };
      // decryption using RSA key should fail
      await expect(openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: encrypted }),
        decryptionKeys: privateKeyRSA,
        config
      })).to.be.rejectedWith(/Session key decryption failed/);
      // decryption using ECC key should succeed (PKCS1 is not used, so constant time countermeasures are not applied)
      const { data } = await openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: encrypted }),
        decryptionKeys: privateKeyECC,
        config
      });
      expect(data).to.equal(plaintext);
    });

  });

  describe('verify - unit tests', function () {
    let minRSABitsVal;

    beforeEach(async function () {
      minRSABitsVal = openpgp.config.minRSABits;
      openpgp.config.minRSABits = 512;
    });

    afterEach(function () {
      openpgp.config.minRSABits = minRSABitsVal;
    });

    describe('message', function () {
      verifyTests(false);

      it('verify should succeed with valid signature (expectSigned=true, with streaming)', async function () {
        const publicKey = await openpgp.readKey({ armoredKey: pub_key });
        const privateKey = await openpgp.decryptKey({
          privateKey: await openpgp.readKey({ armoredKey: priv_key }),
          passphrase
        });

        const signed = await openpgp.sign({
          message: await openpgp.createMessage({ text: plaintext }),
          signingKeys: privateKey
        });
        const { data: streamedData, signatures } = await openpgp.verify({
          message: await openpgp.readMessage({ armoredMessage: stream.toStream(signed) }),
          verificationKeys: publicKey,
          expectSigned: true
        });
        const data = await stream.readToEnd(streamedData);
        expect(data).to.equal(plaintext);
        expect(await signatures[0].verified).to.be.true;
      });

      it('verify should throw on missing signature (expectSigned=true, with streaming)', async function () {

        const publicKey = await openpgp.readKey({ armoredKey: pub_key });

        await expect(openpgp.verify({
          message: await openpgp.createMessage({ text: stream.toStream(plaintext) }),
          verificationKeys: publicKey,
          expectSigned: true
        })).to.be.eventually.rejectedWith(/Message is not signed/);
      });

      it('verify should throw on invalid signature (expectSigned=true, with streaming)', async function () {
        const wrongPublicKey = (await openpgp.readKey({ armoredKey: priv_key_2000_2008 })).toPublic();
        const privateKey = await openpgp.decryptKey({
          privateKey: await openpgp.readKey({ armoredKey: priv_key }),
          passphrase
        });

        const signed = await openpgp.sign({
          message: await openpgp.createMessage({ text: plaintext }),
          signingKeys: privateKey
        });
        const { data: streamedData } = await openpgp.verify({
          message: await openpgp.readMessage({ armoredMessage: stream.toStream(signed) }),
          verificationKeys: wrongPublicKey,
          expectSigned: true
        });
        await expect(
          stream.readToEnd(streamedData)
        ).to.be.eventually.rejectedWith(/Could not find signing key/);
      });

      it('verify should fail if the signature is re-used with a different message', async function () {
        const privateKey = await openpgp.decryptKey({
          privateKey: await openpgp.readKey({ armoredKey: priv_key }),
          passphrase
        });

        const message = await openpgp.createMessage({ text: 'a message' });
        const armoredSignature = await openpgp.sign({
          message,
          signingKeys: privateKey,
          detached: true
        });
        const { signatures } = await openpgp.verify({
          message,
          signature: await openpgp.readSignature({ armoredSignature }),
          verificationKeys: privateKey.toPublic()
        });
        expect(await signatures[0].verified).to.be.true;
        // pass a different message
        await expect(openpgp.verify({
          message: await openpgp.createMessage({ text: 'a different message' }),
          signature: await openpgp.readSignature({ armoredSignature }),
          verificationKeys: privateKey.toPublic(),
          expectSigned: true
        })).to.be.rejectedWith(/digest did not match/);
      });
    });

    describe('cleartext message', function () {
      verifyTests(true);
    });

    function verifyTests(useCleartext) {
      const createMessage = useCleartext ? openpgp.createCleartextMessage : openpgp.createMessage;
      const readMessage = ({ armoredMessage }) => (
        useCleartext ?
          openpgp.readCleartextMessage({ cleartextMessage: armoredMessage }) :
          openpgp.readMessage({ armoredMessage })
      );
      const text = useCleartext ? util.removeTrailingSpaces(plaintext) : plaintext;

      it('verify should succeed with valid signature (expectSigned=true)', async function () {
        const publicKey = await openpgp.readKey({ armoredKey: pub_key });
        const privateKey = await openpgp.decryptKey({
          privateKey: await openpgp.readKey({ armoredKey: priv_key }),
          passphrase
        });

        const signed = await openpgp.sign({
          message: await createMessage({ text }),
          signingKeys: privateKey
        });
        const { data, signatures } = await openpgp.verify({
          message: await readMessage({ armoredMessage: signed }),
          verificationKeys: publicKey,
          expectSigned: true
        });
        expect(data).to.equal(text);
        expect(await signatures[0].verified).to.be.true;
      });

      it('verify should throw on missing signature (expectSigned=true)', async function () {
        const publicKey = await openpgp.readKey({ armoredKey: pub_key });

        await expect(openpgp.verify({
          message: await createMessage({ text }),
          verificationKeys: publicKey,
          expectSigned: true
        })).to.be.eventually.rejectedWith(/Message is not signed/);
      });

      it('verify should throw on invalid signature (expectSigned=true)', async function () {
        const wrongPublicKey = (await openpgp.readKey({ armoredKey: priv_key_2000_2008 })).toPublic();
        const privateKey = await openpgp.decryptKey({
          privateKey: await openpgp.readKey({ armoredKey: priv_key }),
          passphrase
        });

        const signed = await openpgp.sign({
          message: await createMessage({ text }),
          signingKeys: privateKey
        });
        await expect(openpgp.verify({
          message: await readMessage({ armoredMessage: signed }),
          verificationKeys: wrongPublicKey,
          expectSigned: true
        })).to.be.eventually.rejectedWith(/Could not find signing key/);
      });
    }
  });

  describe('sign - unit tests', function () {
    it('Supports signing with GnuPG dummy key', async function () {
      const dummyKey = await openpgp.readKey({ armoredKey: gnuDummyKeySigningSubkey });
      const sig = await openpgp.sign({
        message: await openpgp.createMessage({ text: 'test' }),
        signingKeys: dummyKey,
        date: new Date('2018-12-17T03:24:00'),
        config: { minRSABits: 1024 }
      });
      expect(sig).to.match(/-----END PGP MESSAGE-----\n$/);
    });

    it('Calling sign with no signing key leads to exception', async function () {
      await expect(openpgp.sign({
        message: await openpgp.createMessage({ text: plaintext })
      })).to.be.rejectedWith(/No signing keys provided/);
    });

    it('should output cleartext message of expected format', async function () {
      const text = 'test';
      const message = await openpgp.createCleartextMessage({ text });
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });
      const config = { minRSABits: 1024 };

      const cleartextMessage = await openpgp.sign({ message, signingKeys: privateKey, config, format: 'armored' });
      const parsedArmored = await openpgp.readCleartextMessage({ cleartextMessage });
      expect(parsedArmored.text).to.equal(text);
      expect(parsedArmored.signature.packets.filterByTag(openpgp.enums.packet.signature)).to.have.length(1);

      await expect(openpgp.sign({ message, signingKeys: privateKey, config, format: 'binary' })).to.be.rejectedWith('');

      const objectMessage = await openpgp.sign({ message, signingKeys: privateKey, config, format: 'object' });
      expect(objectMessage.signature.packets.filterByTag(openpgp.enums.packet.signature)).to.have.length(1);
      const verified = await openpgp.verify({
        message: objectMessage,
        verificationKeys: privateKey,
        expectSigned: true,
        config
      });
      expect(verified.data).to.equal(text);
    });

    it('should output message of expected format', async function () {
      const text = 'test';
      const message = await openpgp.createMessage({ text });
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });
      const config = { minRSABits: 1024 };

      const armoredMessage = await openpgp.sign({ message, signingKeys: privateKey, config, format: 'armored' });
      const parsedArmored = await openpgp.readMessage({ armoredMessage });
      expect(parsedArmored.packets.filterByTag(openpgp.enums.packet.onePassSignature)).to.have.length(1);

      const binaryMessage = await openpgp.sign({ message, signingKeys: privateKey, config, format: 'binary' });
      const parsedBinary = await openpgp.readMessage({ binaryMessage });
      expect(parsedBinary.packets.filterByTag(openpgp.enums.packet.onePassSignature)).to.have.length(1);

      const objectMessage = await openpgp.sign({ message, signingKeys: privateKey, config, format: 'object' });
      expect(objectMessage.packets.filterByTag(openpgp.enums.packet.onePassSignature)).to.have.length(1);
      const verified = await openpgp.verify({
        message: objectMessage,
        verificationKeys: privateKey,
        expectSigned: true,
        config
      });
      expect(verified.data).to.equal(text);
    });

    it('should output message of expected format', async function () {
      const text = 'test';
      const message = await openpgp.createMessage({ text });
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });
      const config = { minRSABits: 1024 };

      const armoredMessage = await openpgp.sign({ message, signingKeys: privateKey, config, format: 'armored' });
      const parsedArmored = await openpgp.readMessage({ armoredMessage });
      expect(parsedArmored.packets.filterByTag(openpgp.enums.packet.onePassSignature)).to.have.length(1);

      const binaryMessage = await openpgp.sign({ message, signingKeys: privateKey, config, format: 'binary' });
      const parsedBinary = await openpgp.readMessage({ binaryMessage });
      expect(parsedBinary.packets.filterByTag(openpgp.enums.packet.onePassSignature)).to.have.length(1);

      const objectMessage = await openpgp.sign({ message, signingKeys: privateKey, config, format: 'object' });
      expect(objectMessage.packets.filterByTag(openpgp.enums.packet.onePassSignature)).to.have.length(1);
      const verified = await openpgp.verify({
        message: objectMessage,
        verificationKeys: privateKey,
        expectSigned: true,
        config
      });
      expect(verified.data).to.equal(text);
    });

    it('should output message of expected format (with streaming)', async function () {
      const text = 'test';
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });
      const config = { minRSABits: 1024 };

      const armoredMessage = await openpgp.sign({
        message: await openpgp.createMessage({ text: stream.toStream(text) }),
        signingKeys: privateKey,
        format: 'armored',
        config
      });
      const parsedArmored = await openpgp.readMessage({ armoredMessage });
      expect(parsedArmored.packets.filterByTag(openpgp.enums.packet.onePassSignature)).to.have.length(1);

      const binaryMessage = await openpgp.sign({
        message: await openpgp.createMessage({ text: stream.toStream(text) }),
        signingKeys: privateKey,
        format: 'binary',
        config
      });
      const parsedBinary = await openpgp.readMessage({ binaryMessage });
      expect(parsedBinary.packets.filterByTag(openpgp.enums.packet.onePassSignature)).to.have.length(1);

      const objectMessage = await openpgp.sign({
        message: await openpgp.createMessage({ text: stream.toStream(text) }),
        signingKeys: privateKey,
        format: 'object',
        config
      });
      expect(objectMessage.packets.filterByTag(openpgp.enums.packet.onePassSignature)).to.have.length(1);
      objectMessage.packets[1].data = await stream.readToEnd(objectMessage.packets[1].data);
      objectMessage.packets[2].signedHashValue = await stream.readToEnd(objectMessage.packets[2].signedHashValue);
      const { data: streamedData } = await openpgp.verify({
        message: objectMessage,
        verificationKeys: privateKey,
        expectSigned: true,
        config
      });
      expect(await stream.readToEnd(streamedData)).to.equal(text);
      expect(streamedData).to.equal(text);
    });

    it('should output message of expected format (detached)', async function () {
      const text = 'test';
      const message = await openpgp.createMessage({ text });
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });
      const config = { minRSABits: 1024 };

      const armoredSignature = await openpgp.sign({
        message,
        signingKeys: privateKey,
        detached: true,
        config,
        format: 'armored'
      });
      const parsedArmored = await openpgp.readSignature({ armoredSignature });
      expect(parsedArmored.packets.filterByTag(openpgp.enums.packet.signature)).to.have.length(1);

      const binarySignature = await openpgp.sign({
        message,
        signingKeys: privateKey,
        detached: true,
        config,
        format: 'binary'
      });
      const parsedBinary = await openpgp.readSignature({ binarySignature });
      expect(parsedBinary.packets.filterByTag(openpgp.enums.packet.signature)).to.have.length(1);

      const objectSignature = await openpgp.sign({
        message,
        signingKeys: privateKey,
        detached: true,
        config,
        format: 'object'
      });
      expect(objectSignature.packets.filterByTag(openpgp.enums.packet.signature)).to.have.length(1);
      const verified = await openpgp.verify({
        message,
        signature: objectSignature,
        verificationKeys: privateKey,
        expectSigned: true,
        config
      });
      expect(verified.data).to.equal(text);
    });

    it('should output message of expected format (detached, with streaming)', async function () {
      const text = 'test';
      const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readKey({ armoredKey: priv_key }),
        passphrase
      });
      const config = { minRSABits: 1024 };

      const armoredSignature = await openpgp.sign({
        message: await openpgp.createMessage({ text: stream.toStream(text) }),
        signingKeys: privateKey,
        detached: true,
        format: 'armored',
        config
      });
      const parsedArmored = await openpgp.readSignature({ armoredSignature: await stream.readToEnd(armoredSignature) });
      expect(parsedArmored.packets.filterByTag(openpgp.enums.packet.signature)).to.have.length(1);

      const binarySignature = await openpgp.sign({
        message: await openpgp.createMessage({ text: stream.toStream(text) }),
        signingKeys: privateKey,
        detached: true,
        format: 'binary',
        config
      });
      const parsedBinary = await openpgp.readSignature({ binarySignature: await stream.readToEnd(binarySignature) });
      expect(parsedBinary.packets.filterByTag(openpgp.enums.packet.signature)).to.have.length(1);

      const streamedMessage = await openpgp.createMessage({ text: stream.toStream(text) });
      const objectSignature = await openpgp.sign({
        message: streamedMessage,
        signingKeys: privateKey,
        detached: true,
        format: 'object',
        config
      });
      expect(objectSignature.packets.filterByTag(openpgp.enums.packet.signature)).to.have.length(1);

      const armoredStreamedMessage = streamedMessage.armor(); // consume input message stream, to allow to read the signed hash
      objectSignature.packets[0].signedHashValue = await stream.readToEnd(objectSignature.packets[0].signedHashValue);
      const { data: streamedData } = await openpgp.verify({
        message: await openpgp.readMessage({ armoredMessage: armoredStreamedMessage }),
        signature: objectSignature,
        verificationKeys: privateKey,
        expectSigned: true,
        config
      });
      expect(await stream.readToEnd(streamedData)).to.equal(text);
    });
  });
*/


  });

});
