import express from 'express';
import { generateMyRsaKeys } from './index';
const app = express();
const port = 3000;
const bitLength = 2048;
const keysPromise = generateMyRsaKeys(bitLength);
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With');
    next();
});
// Generem les claus RSA
app.get('/publicKey', async (req, res) => {
    const keyPair = await keysPromise;
    res.json(keyPair.publicKey.toJSON());
    console.log('Generating RSA keys...');
    /*const bitlength = 2048;
    const { publicKey, privateKey } = await generateMyRsaKeys(bitlength);
    console.log('RSA keys generated:');
    console.log('Public key:', publicKey);
    console.log('Private key:', privateKey);*/
    console.log('KeyPair:', keyPair);
    res.json({
        publicKey: {
            e: keyPair.toString()
        }
    });
});
//encriptar
/*app.post('/encrypt', async (req, res) => {
  const { message, e, n } = req.body || {};

  if (!message || !e || !n) {
    return res.status(400).json({ error: 'Invalid request body' });
  }

  const publicKey = MyRsaPublicKey.fromJSON(jsonKey);
  const encrypted = publicKey.encrypt(BigInt(message));
  res.json({ encrypted: encrypted.toString() });
});
//decrypt
app.post('/decrypt', async (req, res) => {
  const { ciphertext, key } = req.body;
  const privateKey = new MyRsaPrivateKey(BigInt(key.d), BigInt(key.n));
  const decrypted = privateKey.decrypt(BigInt(ciphertext));
  res.json({ decrypted: decrypted.toString() });
});
//sign
app.post('/sign', async (req, res) => {
  const { message, key } = req.body;
  const privateKey = new MyRsaPrivateKey(BigInt(key.d), BigInt(key.n));
  const signature = privateKey.sign(BigInt(message));
  res.json({ signature: signature.toString() });
});
//verify
app.get('/verify', async (req, res) => {
  const message = BigInt(req.query.message);
  const signature = BigInt(req.query.signature);
  const publicKey = new MyRsaPublicKey(BigInt(req.query.e), BigInt(req.query.n));
  const verified = publicKey.verify(signature);
  res.json({
    message: message.toString(),
    signature: signature.toString(),
    publicKey: publicKey.toString(),
    verified: (verified === message)
  });
});*/
app.listen(port, () => {
    console.log(`listening on port ${port}`);
});
