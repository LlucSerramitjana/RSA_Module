import * as bcu from 'bigint-crypto-utils';
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
