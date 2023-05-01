"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const index_1 = require("./index");
const index_2 = require("./index");
const paillier_bigint_1 = require("paillier-bigint");
const app = (0, express_1.default)();
const port = 3000;
app.get('/paillier-keys', async (req, res) => {
    const keys = await (0, index_2.generatePaillierKeys)(1024);
    res.json(keys);
});
app.get('/paillier-encrypt', async (req, res) => {
    const m = BigInt(req.query.m);
    const publicKey = new paillier_bigint_1.PublicKey(BigInt(req.query.n), BigInt(req.query.g));
    const c = await (0, index_2.encryptPaillier)(m, publicKey);
    res.json({ c: c.toString() });
});
app.get('/paillier-decrypt', async (req, res) => {
    const c = BigInt(req.query.c);
    const keyPair = await (0, index_2.generatePaillierKeys)(1024);
    const privateKey = keyPair.privateKey;
    const m = await (0, index_2.decryptPaillier)(c, keyPair.publicKey, privateKey);
    res.json({ m: m.toString() });
});
app.get('/paillier-add', async (req, res) => {
    const c1 = BigInt(req.query.c1);
    const c2 = BigInt(req.query.c2);
    const publicKey = new paillier_bigint_1.PublicKey(BigInt(req.query.n), BigInt(req.query.g));
    const c = await (0, index_2.addPaillier)(c1, c2, publicKey);
    res.json({ c: c.toString() });
});
app.get('/rsa-keys', async (req, res) => {
    const bitlength = Number(req.query.bitlength);
    const keys = await (0, index_1.generateMyRsaKeys)(bitlength);
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
    const { publicKey } = await (0, index_1.generateMyRsaKeys)(1024);
    const c = publicKey.encrypt(m);
    res.json({ c: c.toString() });
});
app.get('/rsa-decrypt', async (req, res) => {
    const c = BigInt(req.query.c);
    const { privateKey } = await (0, index_1.generateMyRsaKeys)(1024);
    const m = privateKey.decrypt(c);
    res.json({ m: m.toString() });
});
app.get('/rsa-sign', async (req, res) => {
    const m = BigInt(req.query.m);
    const { privateKey } = await (0, index_1.generateMyRsaKeys)(1024);
    const s = privateKey.sign(m);
    res.json({ s: s.toString() });
});
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
