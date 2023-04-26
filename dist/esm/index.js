import * as bcu from 'bigint-crypto-utils';
import * as paillier from 'paillier-bigint';
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
export async function generateMyRsaKeys(bitlength) {
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
export async function generatePaillierKeys(bitlength) {
    const keys = await paillier.generateRandomKeysSync(bitlength);
    return {
        publicKey: keys.publicKey,
        privateKey: keys.privateKey
    };
}
export async function encryptPaillier(m, publicKey) {
    const c = publicKey.encrypt(m);
    return c;
}
export async function decryptPaillier(c, publicKey, privateKey) {
    const m = privateKey.decrypt(c);
    return m;
}
export async function addPaillier(c1, c2, publicKey) {
    const c = publicKey.addition(c1, c2);
    return c;
}
