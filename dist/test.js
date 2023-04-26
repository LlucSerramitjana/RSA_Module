"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const bcu = __importStar(require("bigint-crypto-utils"));
const index_1 = require("./index");
const index_2 = require("./index");
async function test() {
    const bitlength = 2048;
    const { publicKey, privateKey } = await (0, index_1.generateMyRsaKeys)(bitlength);
    // Test RSA encryption and decryption
    const plaintext = 123456n; //número que vulguem encryptar/desencryptar
    const ciphertext = publicKey.encrypt(plaintext);
    const decryptedtext = privateKey.decrypt(ciphertext);
    console.log('Plaintext:', plaintext.toString());
    console.log('Ciphertext:', ciphertext.toString());
    console.log('Decryptedtext:', decryptedtext.toString());
    // Test RSA signing and verification
    const message = 654321n; //número que vulguem signar/verificar
    const signature = privateKey.sign(message);
    const verified = publicKey.verify(signature);
    console.log('Message:', message.toString());
    console.log('Signature:', signature.toString());
    console.log('Verified:', verified.toString());
    // Test RSA blind signing
    const blindingFactor = await bcu.prime(256);
    const blindedMessage = (message * bcu.modPow(blindingFactor, publicKey.e, publicKey.n)) % publicKey.n;
    const blindedSignature = privateKey.sign(blindedMessage);
    const unblindedSignature = (blindedSignature * bcu.modInv(blindingFactor, publicKey.n)) % publicKey.n;
    const blindVerified = publicKey.verify(unblindedSignature);
    console.log('Blinded Message:', blindedMessage.toString());
    console.log('Blinded Signature:', blindedSignature.toString());
    console.log('Unblinded Signature:', unblindedSignature.toString());
    console.log('Blind Verified:', blindVerified.toString());
    // Test Paillier key generation
    const paillierBitlength = 2048;
    const { publicKey: paillierPublicKey, privateKey: paillierPrivateKey } = await (0, index_2.generatePaillierKeys)(paillierBitlength);
    console.log('Paillier Public Key:', paillierPublicKey);
    console.log('Paillier Private Key:', paillierPrivateKey);
    // Test Paillier encryption and decryption
    const paillierPlaintext1 = 123456n;
    const paillierPlaintext2 = 789012n;
    const paillierCiphertext1 = await (0, index_2.encryptPaillier)(paillierPlaintext1, paillierPublicKey);
    const paillierCiphertext2 = await (0, index_2.encryptPaillier)(paillierPlaintext2, paillierPublicKey);
    const paillierDecryptedtext1 = await (0, index_2.decryptPaillier)(paillierCiphertext1, paillierPublicKey, paillierPrivateKey);
    const paillierDecryptedtext2 = await (0, index_2.decryptPaillier)(paillierCiphertext2, paillierPublicKey, paillierPrivateKey);
    console.log('Paillier Plaintext 1:', paillierPlaintext1.toString());
    console.log('Paillier Plaintext 2:', paillierPlaintext2.toString());
    console.log('Paillier Ciphertext 1:', paillierCiphertext1.toString());
    console.log('Paillier Ciphertext 2:', paillierCiphertext2.toString());
    console.log('Paillier Decryptedtext 1:', paillierDecryptedtext1.toString());
    console.log('Paillier Decryptedtext 2:', paillierDecryptedtext2.toString());
    // Test Paillier addition
    const paillierPlaintext3 = 13579n;
    const paillierCiphertext3 = await (0, index_2.encryptPaillier)(paillierPlaintext3, paillierPublicKey);
    const paillierSum1 = await (0, index_2.addPaillier)(paillierCiphertext1, paillierCiphertext2, paillierPublicKey);
    const paillierSum2 = await (0, index_2.addPaillier)(paillierSum1, paillierCiphertext3, paillierPublicKey);
    const paillierDecryptedSum1 = await (0, index_2.decryptPaillier)(paillierSum1, paillierPublicKey, paillierPrivateKey);
    const paillierDecryptedSum2 = await (0, index_2.decryptPaillier)(paillierSum2, paillierPublicKey, paillierPrivateKey);
    console.log('Paillier Plaintext 3:', paillierPlaintext3.toString());
    console.log('Paillier Ciphertext 3:', paillierCiphertext3.toString());
    console.log('Paillier Sum 1:', paillierSum1.toString());
    console.log('Paillier Sum 2:', paillierSum2.toString());
    console.log('Paillier Decrypted Sum 1:', paillierDecryptedSum1.toString());
    console.log('Paillier Decrypted Sum 2:', paillierDecryptedSum2.toString());
}
test();
//npx ts-node test.ts
