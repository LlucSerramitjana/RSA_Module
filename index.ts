import * as bcu from 'bigint-crypto-utils'

class MyRsaPublicKey {
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
}
class MyRsaPrivateKey {
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
}
interface KeyPair{
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
