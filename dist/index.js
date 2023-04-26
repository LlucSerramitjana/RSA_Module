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
exports.addPaillier = exports.decryptPaillier = exports.encryptPaillier = exports.generatePaillierKeys = exports.generateMyRsaKeys = void 0;
const bcu = __importStar(require("bigint-crypto-utils"));
const paillier = __importStar(require("paillier-bigint"));
class MyRsaPublicKey {
    constructor(e, n) {
        this.e = e;
        this.n = n;
    }
    encrypt(m) {
        const c = bcu.modPow(m, this.e, this.n);
        return c;
    }
    verify(s) {
        const m = bcu.modPow(s, this.e, this.n);
        return m;
    }
}
class MyRsaPrivateKey {
    constructor(d, n) {
        this.d = d;
        this.n = n;
    }
    decrypt(c) {
        const m = bcu.modPow(c, this.d, this.n);
        return m;
    }
    sign(m) {
        const s = bcu.modPow(m, this.d, this.n);
        return s;
    }
}
async function generateMyRsaKeys(bitlength) {
    const p = await bcu.prime(Math.floor(bitlength / 2));
    const q = await bcu.prime(Math.floor(bitlength / 2) + 1);
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    const e = 65537n;
    const d = await bcu.modInv(e, phi);
    return {
        publicKey: new MyRsaPublicKey(e, n),
        privateKey: new MyRsaPrivateKey(d, n)
    };
}
exports.generateMyRsaKeys = generateMyRsaKeys;
async function generatePaillierKeys(bitlength) {
    const keys = await paillier.generateRandomKeysSync(bitlength);
    return {
        publicKey: keys.publicKey,
        privateKey: keys.privateKey
    };
}
exports.generatePaillierKeys = generatePaillierKeys;
async function encryptPaillier(m, publicKey) {
    const c = publicKey.encrypt(m);
    return c;
}
exports.encryptPaillier = encryptPaillier;
async function decryptPaillier(c, publicKey, privateKey) {
    const m = privateKey.decrypt(c);
    return m;
}
exports.decryptPaillier = decryptPaillier;
async function addPaillier(c1, c2, publicKey) {
    const c = publicKey.addition(c1, c2);
    return c;
}
exports.addPaillier = addPaillier;
