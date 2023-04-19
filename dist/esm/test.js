import { generateMyRsaKeys } from './index';
async function test() {
    const bitlength = 2048;
    const { publicKey, privateKey } = await generateMyRsaKeys(bitlength);
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
}
test();
//npx ts-node test.ts
