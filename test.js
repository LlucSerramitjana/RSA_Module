"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
var bcu = require("bigint-crypto-utils");
var index_1 = require("./index");
var index_2 = require("./index");
function test() {
    return __awaiter(this, void 0, void 0, function () {
        var bitlength, _a, publicKey, privateKey, plaintext, ciphertext, decryptedtext, message, signature, verified, blindingFactor, blindedMessage, blindedSignature, unblindedSignature, blindVerified, paillierBitlength, _b, paillierPublicKey, paillierPrivateKey, paillierPlaintext1, paillierPlaintext2, paillierCiphertext1, paillierCiphertext2, paillierDecryptedtext1, paillierDecryptedtext2, paillierPlaintext3, paillierCiphertext3, paillierSum1, paillierSum2, paillierDecryptedSum1, paillierDecryptedSum2;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    bitlength = 2048;
                    return [4 /*yield*/, (0, index_1.generateMyRsaKeys)(bitlength)
                        // Test RSA encryption and decryption
                    ];
                case 1:
                    _a = _c.sent(), publicKey = _a.publicKey, privateKey = _a.privateKey;
                    plaintext = 123456n //número que vulguem encryptar/desencryptar
                    ;
                    ciphertext = publicKey.encrypt(plaintext);
                    decryptedtext = privateKey.decrypt(ciphertext);
                    console.log('Plaintext:', plaintext.toString());
                    console.log('Ciphertext:', ciphertext.toString());
                    console.log('Decryptedtext:', decryptedtext.toString());
                    message = 654321n //número que vulguem signar/verificar
                    ;
                    signature = privateKey.sign(message);
                    verified = publicKey.verify(signature);
                    console.log('Message:', message.toString());
                    console.log('Signature:', signature.toString());
                    console.log('Verified:', verified.toString());
                    return [4 /*yield*/, bcu.prime(256)];
                case 2:
                    blindingFactor = _c.sent();
                    blindedMessage = (message * bcu.modPow(blindingFactor, publicKey.e, publicKey.n)) % publicKey.n;
                    blindedSignature = privateKey.sign(blindedMessage);
                    unblindedSignature = (blindedSignature * bcu.modInv(blindingFactor, publicKey.n)) % publicKey.n;
                    blindVerified = publicKey.verify(unblindedSignature);
                    console.log('Blinded Message:', blindedMessage.toString());
                    console.log('Blinded Signature:', blindedSignature.toString());
                    console.log('Unblinded Signature:', unblindedSignature.toString());
                    console.log('Blind Verified:', blindVerified.toString());
                    paillierBitlength = 2048;
                    return [4 /*yield*/, (0, index_2.generatePaillierKeys)(paillierBitlength)];
                case 3:
                    _b = _c.sent(), paillierPublicKey = _b.publicKey, paillierPrivateKey = _b.privateKey;
                    console.log('Paillier Public Key:', paillierPublicKey);
                    console.log('Paillier Private Key:', paillierPrivateKey);
                    paillierPlaintext1 = 123456n;
                    paillierPlaintext2 = 789012n;
                    return [4 /*yield*/, (0, index_2.encryptPaillier)(paillierPlaintext1, paillierPublicKey)];
                case 4:
                    paillierCiphertext1 = _c.sent();
                    return [4 /*yield*/, (0, index_2.encryptPaillier)(paillierPlaintext2, paillierPublicKey)];
                case 5:
                    paillierCiphertext2 = _c.sent();
                    return [4 /*yield*/, (0, index_2.decryptPaillier)(paillierCiphertext1, paillierPublicKey, paillierPrivateKey)];
                case 6:
                    paillierDecryptedtext1 = _c.sent();
                    return [4 /*yield*/, (0, index_2.decryptPaillier)(paillierCiphertext2, paillierPublicKey, paillierPrivateKey)];
                case 7:
                    paillierDecryptedtext2 = _c.sent();
                    console.log('Paillier Plaintext 1:', paillierPlaintext1.toString());
                    console.log('Paillier Plaintext 2:', paillierPlaintext2.toString());
                    console.log('Paillier Ciphertext 1:', paillierCiphertext1.toString());
                    console.log('Paillier Ciphertext 2:', paillierCiphertext2.toString());
                    console.log('Paillier Decryptedtext 1:', paillierDecryptedtext1.toString());
                    console.log('Paillier Decryptedtext 2:', paillierDecryptedtext2.toString());
                    paillierPlaintext3 = 13579n;
                    return [4 /*yield*/, (0, index_2.encryptPaillier)(paillierPlaintext3, paillierPublicKey)];
                case 8:
                    paillierCiphertext3 = _c.sent();
                    return [4 /*yield*/, (0, index_2.addPaillier)(paillierCiphertext1, paillierCiphertext2, paillierPublicKey)];
                case 9:
                    paillierSum1 = _c.sent();
                    return [4 /*yield*/, (0, index_2.addPaillier)(paillierSum1, paillierCiphertext3, paillierPublicKey)];
                case 10:
                    paillierSum2 = _c.sent();
                    return [4 /*yield*/, (0, index_2.decryptPaillier)(paillierSum1, paillierPublicKey, paillierPrivateKey)];
                case 11:
                    paillierDecryptedSum1 = _c.sent();
                    return [4 /*yield*/, (0, index_2.decryptPaillier)(paillierSum2, paillierPublicKey, paillierPrivateKey)];
                case 12:
                    paillierDecryptedSum2 = _c.sent();
                    console.log('Paillier Plaintext 3:', paillierPlaintext3.toString());
                    console.log('Paillier Ciphertext 3:', paillierCiphertext3.toString());
                    console.log('Paillier Sum 1:', paillierSum1.toString());
                    console.log('Paillier Sum 2:', paillierSum2.toString());
                    console.log('Paillier Decrypted Sum 1:', paillierDecryptedSum1.toString());
                    console.log('Paillier Decrypted Sum 2:', paillierDecryptedSum2.toString());
                    return [2 /*return*/];
            }
        });
    });
}
test();
//npx ts-node test.ts
