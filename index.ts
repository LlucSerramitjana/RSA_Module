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

  constructor(e: bigint, n: bigint) {
    this.e = e
    this.n = n
  }

  encrypt(m: bigint): bigint {
    const c = bcu.modPow(m, this.e, this.n)
    return c
  }
  verify(s: bigint): bigint {
    const m = bcu.modPow(s, this.e, this.n)
    return m
  }

  toJSON(): MyRsaJsonPublicKey {
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

  constructor(d: bigint, n: bigint) {
    this.d = d
    this.n = n
  }

  decrypt(c: bigint): bigint {
    const m = bcu.modPow(c, this.d, this.n)
    return m
  }
  sign(m: bigint): bigint {
    const s = bcu.modPow(m, this.d, this.n)
    return s
  }

  toJSON() {
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





export interface KeyPair {
  publicKey: MyRsaPublicKey
  privateKey: MyRsaPrivateKey
}
export async function generateMyRsaKeys(bitlength: number): Promise<KeyPair> {
  const p = await bcu.prime(Math.floor(bitlength / 2))
  const q = await bcu.prime(Math.floor(bitlength / 2) + 1)
  const n = p * q
  const phi = (p - 1n) * (q - 1n)
  const e = 65537n
  const d = await bcu.modInv(e, phi)

  return {
    publicKey: new MyRsaPublicKey(e, n),
    privateKey: new MyRsaPrivateKey(d, n)
  }
}


export interface PaillierKeyPair {
  publicKey: MyPaillierPublicKey,
  privateKey: paillier.PrivateKey
}
export interface MyJsonPaillierPublicKey {
  n: string // base64
  _n2: string // base64
  g: string // base64
}

export class MyPaillierPublicKey {
    n: bigint
    g: bigint

  readonly _n2: bigint


  constructor(n: bigint, g: bigint) {
    this.n = n
    this._n2 = this.n ** 2n
    this.g = g
  }

  get bitLength(): number {
    return bcu.bitLength(this.n)
  }

  encrypt(m: bigint, r?: bigint): bigint {
    if (r === undefined) {
      do {
        r = bcu.randBetween(this.n)
      } while (bcu.gcd(r, this.n) !== 1n)
    }
    return (bcu.modPow(this.g, m, this._n2) * bcu.modPow(r, this.n, this._n2)) % this._n2
  }

  addition(...ciphertexts: bigint[]): bigint {
    return ciphertexts.reduce((sum, next) => sum * next % this._n2, 1n)
  }

  plaintextAddition(ciphertext: bigint, ...plaintexts: bigint[]): bigint {
    return plaintexts.reduce((sum, next) => sum * bcu.modPow(this.g, next, this._n2) % this._n2, ciphertext)
  }

  multiply(c: bigint, k: bigint | number): bigint {
    return bcu.modPow(c, k, this._n2)
  }

  toJSON() {
    return {
      n: bc.bigintToBase64(this.n),
      _n2: bc.bigintToBase64(this._n2),
      g: bc.bigintToBase64(this.g)
    }
  }
  static fromJSON(jsonKey: any) {
    const n = bc.base64ToBigint(jsonKey.n)
    const g = bc.base64ToBigint(jsonKey.g)
    return new MyPaillierPublicKey(n, g)
  }
}
export interface MyJsonPaillierPrivateKey {
  lambda: string // base64
  mu: string // base64
}
export default class MyPaillierPrivateKey {
  readonly lambda: bigint
  readonly mu: bigint
  readonly publicKey: MyPaillierPublicKey
  private readonly _p?: bigint
  private readonly _q?: bigint

  
  constructor (lambda: bigint, mu: bigint, publicKey: MyPaillierPublicKey, p?: bigint, q?: bigint) {
    this.lambda = lambda
    this.mu = mu
    this._p = p
    this._q = q
    this.publicKey = publicKey
  }

  
  get bitLength (): number {
    return bcu.bitLength(this.publicKey.n)
  }

  get n (): bigint {
    return this.publicKey.n
  }

  
  decrypt (c: bigint): bigint {
    return (this.L(bcu.modPow(c, this.lambda, this.publicKey._n2), this.publicKey.n) * this.mu) % this.publicKey.n
  }

  getRandomFactor (c: bigint): bigint {
    if (this.publicKey.g !== this.n + 1n) throw RangeError('Cannot recover the random factor if publicKey.g != publicKey.n + 1. You should generate yout keys using the simple variant, e.g. generateRandomKeys(3072, true) )')
    if (this._p === undefined || this._q === undefined) {
      throw Error('Cannot get random factor without knowing p and q')
    }
    const m = this.decrypt(c)
    const phi = (this._p - 1n) * (this._q - 1n)
    const nInvModPhi = bcu.modInv(this.n, phi)
    const c1 = c * (1n - m * this.n) % this.publicKey._n2
    return bcu.modPow(c1, nInvModPhi, this.n)
  }





  toJSON() {
    return {
      lambda: bc.bigintToBase64(this.lambda),
      mu: bc.bigintToBase64(this.mu)
    }
  }
  static fromJSON(jsonKey: any) {
    const lambda = bc.base64ToBigint(jsonKey.lambda)
    const mu = bc.base64ToBigint(jsonKey.mu)
    const publicKey = MyPaillierPublicKey.fromJSON(jsonKey.publicKey)
    const p = jsonKey.p ? bc.base64ToBigint(jsonKey.p) : undefined
    const q = jsonKey.q ? bc.base64ToBigint(jsonKey.q) : undefined
    return new MyPaillierPrivateKey(lambda, mu, publicKey, p, q)
  }
   L (a: bigint, n: bigint): bigint {
    return (a - 1n) / n
  }

}

export async function generatePaillierKeys(bitlength: number): Promise<PaillierKeyPair> {
  const keys = await paillier.generateRandomKeysSync(bitlength);
  return {
    publicKey: new MyPaillierPublicKey(keys.publicKey.n, keys.publicKey.g),
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


