import * as bcu from 'bigint-crypto-utils'
import * as paillier from 'paillier-bigint'
import * as bc from 'bigint-conversion'

export interface MyRsaJsonPublicKey {
  e: string // base64
  n: string // base64
}

export class MyRsaPublicKey {
  e: bigint
  n: bigint

  constructor(e: bigint, n: bigint){
    this.e = e
    this.n = n
  }

  encrypt (m: bigint): bigint{
    const c = bcu.modPow(m, this.e, this.n)
    return c
  }
  verify (s: bigint): bigint {
    const m = bcu.modPow(s, this.e, this.n)
    return m
  }

  toJSON (): MyRsaJsonPublicKey {
    return {
      e: bc.bigintToBase64(this.e),
      n: bc.bigintToBase64(this.n)
    }
  }

  static fromJSON(jsonKey: MyRsaJsonPublicKey) {
    const e = bc.base64ToBigint(jsonKey.e)
    const n = bc.base64ToBigint(jsonKey.n)
    return new MyRsaPublicKey(e, n)
  }
}
export class MyRsaPrivateKey {
  d: bigint
  n: bigint

  constructor(d: bigint, n: bigint){
    this.d = d
    this.n = n
  }

  decrypt (c: bigint): bigint{
    const m = bcu.modPow(c, this.d, this.n)
    return m
  }
  sign (m: bigint): bigint {
    const s = bcu.modPow(m, this.d, this.n)
    return s
  }
  
  toJSON () {
    return {
      d: bc.bigintToBase64(this.d),
      n: bc.bigintToBase64(this.n)
    }
  }

  static fromJSON(jsonKey: any) {
    const d = bc.base64ToBigint(jsonKey.d)
    const n = bc.base64ToBigint(jsonKey.n)
    return new MyRsaPublicKey(d, n)
  }
}
export interface KeyPair{
  publicKey: MyRsaPublicKey
  privateKey: MyRsaPrivateKey
}
export async function generateMyRsaKeys (bitlength: number): Promise<KeyPair> {
  const p = await bcu.prime(Math.floor(bitlength/2))
  const q = await bcu.prime(Math.floor(bitlength/2)+1)
  const n = p * q
  const phi = (p - 1n) * (q - 1n)
  const e = 65537n
  const d = await bcu.modInv(e, phi)

  return {
    publicKey: new MyRsaPublicKey(e, n),
    privateKey: new MyRsaPrivateKey(d, n)
  }
}


interface PaillierKeyPair {
  publicKey: paillier.PublicKey,
  privateKey: paillier.PrivateKey
}

export async function generatePaillierKeys(bitlength: number): Promise<PaillierKeyPair> {
  const keys = await paillier.generateRandomKeysSync(bitlength);
  return {
    publicKey: keys.publicKey,
    privateKey: keys.privateKey
  }
}

export async function encryptPaillier(m: bigint, publicKey: paillier.PublicKey): Promise<bigint> {
  const c = publicKey.encrypt(m);
  return c;
}

export async function decryptPaillier(c: bigint, publicKey: paillier.PublicKey, privateKey: paillier.PrivateKey): Promise<bigint> {
  const m = privateKey.decrypt(c);
  return m;
}

export async function addPaillier(c1: bigint, c2: bigint, publicKey: paillier.PublicKey): Promise<bigint> {
  const c = publicKey.addition(c1, c2);
  return c;
}
