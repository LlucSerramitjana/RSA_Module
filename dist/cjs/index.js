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
exports.addPaillier = exports.decryptPaillier = exports.encryptPaillier = exports.generatePaillierKeys = exports.MyPaillierPublicKey = exports.generateMyRsaKeys = exports.MyRsaPrivateKey = exports.MyRsaPublicKey = void 0;
const bcu = __importStar(require("bigint-crypto-utils"));
const paillier = __importStar(require("paillier-bigint"));
const bc = __importStar(require("bigint-conversion"));
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
    toJSON() {
        return {
            e: bc.bigintToBase64(this.e),
            n: bc.bigintToBase64(this.n)
        };
    }
    static fromJSON(jsonKey) {
        const e = bc.base64ToBigint(jsonKey.e);
        const n = bc.base64ToBigint(jsonKey.n);
        return new MyRsaPublicKey(e, n);
    }
}
exports.MyRsaPublicKey = MyRsaPublicKey;
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
    toJSON() {
        return {
            d: bc.bigintToBase64(this.d),
            n: bc.bigintToBase64(this.n)
        };
    }
    static fromJSON(jsonKey) {
        const d = bc.base64ToBigint(jsonKey.d);
        const n = bc.base64ToBigint(jsonKey.n);
        return new MyRsaPublicKey(d, n);
    }
}
exports.MyRsaPrivateKey = MyRsaPrivateKey;
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
class MyPaillierPublicKey {
    constructor(n, g) {
        this.n = n;
        this._n2 = this.n ** 2n;
        this.g = g;
    }
    get bitLength() {
        return bcu.bitLength(this.n);
    }
    encrypt(m, r) {
        if (r === undefined) {
            do {
                r = bcu.randBetween(this.n);
            } while (bcu.gcd(r, this.n) !== 1n);
        }
        return (bcu.modPow(this.g, m, this._n2) * bcu.modPow(r, this.n, this._n2)) % this._n2;
    }
    addition(...ciphertexts) {
        return ciphertexts.reduce((sum, next) => sum * next % this._n2, 1n);
    }
    plaintextAddition(ciphertext, ...plaintexts) {
        return plaintexts.reduce((sum, next) => sum * bcu.modPow(this.g, next, this._n2) % this._n2, ciphertext);
    }
    multiply(c, k) {
        return bcu.modPow(c, k, this._n2);
    }
    toJSON() {
        return {
            n: bc.bigintToBase64(this.n),
            _n2: bc.bigintToBase64(this._n2),
            g: bc.bigintToBase64(this.g)
        };
    }
    static fromJSON(jsonKey) {
        const n = bc.base64ToBigint(jsonKey.n);
        const g = bc.base64ToBigint(jsonKey.g);
        return new MyPaillierPublicKey(n, g);
    }
}
exports.MyPaillierPublicKey = MyPaillierPublicKey;
class MyPaillierPrivateKey {
    constructor(lambda, mu, publicKey, p, q) {
        this.lambda = lambda;
        this.mu = mu;
        this._p = p;
        this._q = q;
        this.publicKey = publicKey;
    }
    get bitLength() {
        return bcu.bitLength(this.publicKey.n);
    }
    get n() {
        return this.publicKey.n;
    }
    decrypt(c) {
        return (this.L(bcu.modPow(c, this.lambda, this.publicKey._n2), this.publicKey.n) * this.mu) % this.publicKey.n;
    }
    getRandomFactor(c) {
        if (this.publicKey.g !== this.n + 1n)
            throw RangeError('Cannot recover the random factor if publicKey.g != publicKey.n + 1. You should generate yout keys using the simple variant, e.g. generateRandomKeys(3072, true) )');
        if (this._p === undefined || this._q === undefined) {
            throw Error('Cannot get random factor without knowing p and q');
        }
        const m = this.decrypt(c);
        const phi = (this._p - 1n) * (this._q - 1n);
        const nInvModPhi = bcu.modInv(this.n, phi);
        const c1 = c * (1n - m * this.n) % this.publicKey._n2;
        return bcu.modPow(c1, nInvModPhi, this.n);
    }
    toJSON() {
        return {
            lambda: bc.bigintToBase64(this.lambda),
            mu: bc.bigintToBase64(this.mu)
        };
    }
    static fromJSON(jsonKey) {
        const lambda = bc.base64ToBigint(jsonKey.lambda);
        const mu = bc.base64ToBigint(jsonKey.mu);
        const publicKey = MyPaillierPublicKey.fromJSON(jsonKey.publicKey);
        const p = jsonKey.p ? bc.base64ToBigint(jsonKey.p) : undefined;
        const q = jsonKey.q ? bc.base64ToBigint(jsonKey.q) : undefined;
        return new MyPaillierPrivateKey(lambda, mu, publicKey, p, q);
    }
    L(a, n) {
        return (a - 1n) / n;
    }
}
exports.default = MyPaillierPrivateKey;
async function generatePaillierKeys(bitlength) {
    const keys = await paillier.generateRandomKeysSync(bitlength);
    return {
        publicKey: new MyPaillierPublicKey(keys.publicKey.n, keys.publicKey.g),
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
