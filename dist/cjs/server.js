"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const index_1 = require("./index");
const bc = __importStar(require("bigint-conversion"));
const bcu = __importStar(require("bigint-crypto-utils"));
//node .\dist\cjs\server.js ----------------------------> comanda per arrancar el servidor
const app = (0, express_1.default)();
const port = 3000;
const bitLength = 2048;
const keysPromise = (0, index_1.generateMyRsaKeys)(bitLength);
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With');
    next();
});
// Envia la clau RSA
app.get('/publicKey', async (req, res) => {
    const keyPair = await keysPromise;
    res.json(keyPair.publicKey.toJSON());
    //console.log('Generating RSA keys...');
    /*const bitlength = 2048;
    const { publicKey, privateKey } = await generateMyRsaKeys(bitlength);
    console.log('RSA keys generated:');
    console.log('Public key:', publicKey);
    console.log('Private key:', privateKey);*/
    console.log('KeyPair:', keyPair.publicKey);
    console.log('KeyPair:', keyPair.publicKey.toJSON());
    /*res.json({
      publicKey: {
        e: keyPair.toString()
      }
    });*/
});
app.get('/privateKey', async (req, res) => {
    const keyPair = await keysPromise;
    res.json(keyPair.privateKey.toJSON());
    console.log('KeyPair:', keyPair.privateKey);
    console.log('KeyPair:', keyPair.privateKey.toJSON());
});
//decrypt
app.post('/decrypt', async (req, res) => {
    const { message } = req.body || {};
    const keyPair = await keysPromise;
    if (!message) {
        return res.status(400).json({ error: 'Invalid request body' });
    }
    const decrypted = keyPair.privateKey.decrypt(BigInt(message));
    res.json({ decrypted: decrypted.toString() });
});
app.post('/todecrypt/:message', async (req, res) => {
    console.log('req.params:', req.params);
    console.log("PASA POR AQUI 222222");
    const { message } = req.params;
    console.log('message:', message);
    const keyPair = await keysPromise;
    if (!message) {
        return res.status(400).json({ error: 'Invalid request body' });
    }
    const d = BigInt(message);
    console.log('d:', d);
    const decrypted = keyPair.privateKey.decrypt(BigInt(message));
    console.log('decrypted:', decrypted);
    res.json({ decrypted: decrypted.toString() });
});
app.post('/sign/:message', async (req, res) => {
    console.log('req.params:', req.params);
    const { message } = req.params;
    console.log('message:', message);
    const keyPair = await keysPromise;
    console.log("privateKey:", keyPair.privateKey);
    if (!message) {
        return res.status(400).json({ error: 'Invalid request body' });
    }
    const decrypted = keyPair.privateKey.decrypt(BigInt(message));
    //const privateKey = keyPair.privateKey;
    //console.log('privateKey:', privateKey);
    const signature = keyPair.privateKey.sign(BigInt(message));
    const signature2 = bc.bigintToBase64(signature);
    console.log('signature:', signature2);
    res.json({ signature: signature2.toString() });
});
app.post('/tounblind/:message/:pubKeyn/:pubKeye/:blindingFactor', async (req, res) => {
    console.log('req.params:', req.params);
    const { message } = req.params;
    const { pubKeyn } = req.params;
    const { pubKeye } = req.params;
    const { blindingFactor } = req.params;
    console.log('message:', message);
    console.log('npubKey:', pubKeyn);
    console.log('epubKey:', pubKeye);
    console.log('blindingFactor:', blindingFactor);
    const m = BigInt(message);
    const n = BigInt(pubKeyn);
    const e = BigInt(pubKeye);
    const b = BigInt(blindingFactor);
    console.log('m:', m);
    console.log('n:', n);
    console.log('e:', e);
    console.log('b:', b);
    const unblindedSignature = (m * bcu.modInv(b, n)) % e;
    const u = BigInt(unblindedSignature);
    console.log('unblindedSignature base64:', u);
    //const unblindedSignature = (blindedSignature * bcu.modInv(blindingFactor, publicKey.n)) % publicKey.n;
    //const blindVerified = publicKey.verify(unblindedSignature);
    console.log('unblindedSignature:', unblindedSignature);
    const publicKey = new index_1.MyRsaPublicKey(e, n);
    console.log('publicKey:', publicKey);
    const blindVerified = publicKey.verify(unblindedSignature);
    console.log('blindVerified:', blindVerified);
    res.json({ blindVerified: blindVerified.toString() });
});
/*app.post('/sign', async (req, res) => {
  const { message, key } = req.body;
  const privateKey = new MyRsaPrivateKey(BigInt(key.d), BigInt(key.n));
  const signature = privateKey.sign(BigInt(message));
  res.json({ signature: signature.toString() });
});*/
/*app.post('/toverify/:message' , async (req, res) => {
  console.log('req.params:', req.params)
  const { message } = req.params;
  console.log('message:', message)
  const keyPair = await keysPromise
  if (!message) {
    return res.status(400).json({ error: 'Invalid request body' });
  }
  const d = BigInt(message)
  console.log('d:', d)
  const verified = keyPair.publicKey.verify(BigInt(message));
  console.log('verified:', verified)
  res.json({ verified: verified.toString() });
});*/
//decrypt
/*app.post('/decrypt', async (req, res) => {
  const { ciphertext, key } = req.body;
  const privateKey = new MyRsaPrivateKey(BigInt(key.d), BigInt(key.n));
  const decrypted = privateKey.decrypt(BigInt(ciphertext));
  res.json({ decrypted: decrypted.toString() });
});*/
//verify
/*app.get('/verify', async (req, res) => {
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
