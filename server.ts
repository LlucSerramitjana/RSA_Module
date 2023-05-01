import express from 'express';
import { generateMyRsaKeys } from './index';

const app = express();
const port = 3000;

// Generem les claus RSA
app.get('/generate-rsa-keys', async (req, res) => {
  console.log('Generating RSA keys...');
  const bitlength = 2048;
  const { publicKey, privateKey } = await generateMyRsaKeys(bitlength);
  console.log('RSA keys generated:');
  console.log('Public key:', publicKey);
  console.log('Private key:', privateKey);
  res.json({
    publicKey: publicKey.toString(),
    privateKey: privateKey.toString()
  });
});

app.listen(port, () => {
  console.log(`listening on port ${port}`);
});