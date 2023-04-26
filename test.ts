import * as bcu from 'bigint-crypto-utils';
import { generateMyRsaKeys } from './index';
import * as paillier from 'paillier-bigint';
import { generatePaillierKeys, encryptPaillier, decryptPaillier, addPaillier } from './index';

async function test() {
  const bitlength = 2048
  const { publicKey, privateKey } = await generateMyRsaKeys(bitlength)

  // Test RSA encryption and decryption
  const plaintext = 123456n //número que vulguem encryptar/desencryptar
  const ciphertext = publicKey.encrypt(plaintext)
  const decryptedtext = privateKey.decrypt(ciphertext)
  console.log('Plaintext:', plaintext.toString())
  console.log('Ciphertext:', ciphertext.toString())
  console.log('Decryptedtext:', decryptedtext.toString())

  // Test RSA signing and verification
  const message = 654321n //número que vulguem signar/verificar
  const signature = privateKey.sign(message)
  const verified = publicKey.verify(signature)
  console.log('Message:', message.toString())
  console.log('Signature:', signature.toString())
  console.log('Verified:', verified.toString())

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
  const { publicKey: paillierPublicKey, privateKey: paillierPrivateKey } = await generatePaillierKeys(paillierBitlength);
  console.log('Paillier Public Key:', paillierPublicKey);
  console.log('Paillier Private Key:', paillierPrivateKey);

  // Test Paillier encryption and decryption
  const paillierPlaintext1 = 123456n;
  const paillierPlaintext2 = 789012n;
  const paillierCiphertext1 = await encryptPaillier(paillierPlaintext1, paillierPublicKey);
  const paillierCiphertext2 = await encryptPaillier(paillierPlaintext2, paillierPublicKey);
  const paillierDecryptedtext1 = await decryptPaillier(paillierCiphertext1, paillierPublicKey, paillierPrivateKey);
  const paillierDecryptedtext2 = await decryptPaillier(paillierCiphertext2, paillierPublicKey, paillierPrivateKey);
  console.log('Paillier Plaintext 1:', paillierPlaintext1.toString());
  console.log('Paillier Plaintext 2:', paillierPlaintext2.toString());
  console.log('Paillier Ciphertext 1:', paillierCiphertext1.toString());
  console.log('Paillier Ciphertext 2:', paillierCiphertext2.toString());
  console.log('Paillier Decryptedtext 1:', paillierDecryptedtext1.toString());
  console.log('Paillier Decryptedtext 2:', paillierDecryptedtext2.toString());

  // Test Paillier addition
  const paillierPlaintext3 = 13579n;
  const paillierCiphertext3 = await encryptPaillier(paillierPlaintext3, paillierPublicKey);
  const paillierSum1 = await addPaillier(paillierCiphertext1, paillierCiphertext2, paillierPublicKey);
  const paillierSum2 = await addPaillier(paillierSum1, paillierCiphertext3, paillierPublicKey);
  const paillierDecryptedSum1 = await decryptPaillier(paillierSum1, paillierPublicKey, paillierPrivateKey);
  const paillierDecryptedSum2 = await decryptPaillier(paillierSum2, paillierPublicKey, paillierPrivateKey);
  console.log('Paillier Plaintext 3:', paillierPlaintext3.toString());
  console.log('Paillier Ciphertext 3:', paillierCiphertext3.toString());
  console.log('Paillier Sum 1:', paillierSum1.toString());
  console.log('Paillier Sum 2:', paillierSum2.toString());
  console.log('Paillier Decrypted Sum 1:', paillierDecryptedSum1.toString());
  console.log('Paillier Decrypted Sum 2:', paillierDecryptedSum2.toString());
}

test()
//npx ts-node test.ts