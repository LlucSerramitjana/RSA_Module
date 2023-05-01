import express from 'express';
import { generateMyRsaKeys } from './index';
import { generatePaillierKeys, encryptPaillier, decryptPaillier, addPaillier } from './index';
import { PublicKey as PaillierPublicKey } from 'paillier-bigint';
const app = express();
const port = 3000;
app.get('/paillier-keys', async (req, res) => {
    const keys = await generatePaillierKeys(1024);
    res.json(keys);
});
app.get('/paillier-encrypt', async (req, res) => {
    const m = BigInt(req.query.m);
    const publicKey = new PaillierPublicKey(BigInt(req.query.n), BigInt(req.query.g));
    const c = await encryptPaillier(m, publicKey);
    res.json({ c: c.toString() });
});
app.get('/paillier-decrypt', async (req, res) => {
    const c = BigInt(req.query.c);
    const keyPair = await generatePaillierKeys(1024);
    const privateKey = keyPair.privateKey;
    const m = await decryptPaillier(c, keyPair.publicKey, privateKey);
    res.json({ m: m.toString() });
});
app.get('/paillier-add', async (req, res) => {
    const c1 = BigInt(req.query.c1);
    const c2 = BigInt(req.query.c2);
    const publicKey = new PaillierPublicKey(BigInt(req.query.n), BigInt(req.query.g));
    const c = await addPaillier(c1, c2, publicKey);
    res.json({ c: c.toString() });
});
app.get('/rsa-keys', async (req, res) => {
    const bitlength = Number(req.query.bitlength);
    const keys = await generateMyRsaKeys(bitlength);
    res.json({
        publicKey: {
            e: keys.publicKey.e.toString(),
            n: keys.publicKey.n.toString()
        },
        privateKey: {
            d: keys.privateKey.d.toString(),
            n: keys.privateKey.n.toString()
        }
    });
});
app.get('/rsa-encrypt', async (req, res) => {
    const m = BigInt(req.query.m);
    const { publicKey } = await generateMyRsaKeys(1024);
    const c = publicKey.encrypt(m);
    res.json({ c: c.toString() });
});
app.get('/rsa-decrypt', async (req, res) => {
    const c = BigInt(req.query.c);
    const { privateKey } = await generateMyRsaKeys(1024);
    const m = privateKey.decrypt(c);
    res.json({ m: m.toString() });
});
app.get('/rsa-sign', async (req, res) => {
    const m = BigInt(req.query.m);
    const { privateKey } = await generateMyRsaKeys(1024);
    const s = privateKey.sign(m);
    res.json({ s: s.toString() });
});
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
