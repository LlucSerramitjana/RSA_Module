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
const bc = __importStar(require("bigint-conversion"));
const express_1 = __importDefault(require("express"));
const index_1 = require("./index");
//node .\dist\cjs\server.js ----------------------------> comanda per arrancar el servidor
const app = (0, express_1.default)();
const port = 3000;
const cors = require('cors');
app.use(cors());
app.use(express_1.default.json());
const bitLength = 2048;
const keysPromise = (0, index_1.generateMyRsaKeys)(bitLength);
const paillierKeysPromise = (0, index_1.generatePaillierKeys)(bitLength);
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
    console.log('KeyPair:', keyPair.publicKey);
    console.log('KeyPair:', keyPair.publicKey.toJSON());
});
app.get('/publicKeyPallier', async (req, res) => {
    const pubKey = await paillierKeysPromise;
    res.json(pubKey.publicKey.toJSON());
    console.log('Public key:', pubKey.publicKey);
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
    const signature = keyPair.privateKey.sign(BigInt(message));
    const signature2 = bc.bigintToBase64(signature);
    console.log('signature:', signature2);
    res.json({ signature: signature2.toString() });
});
app.post('/tounblind/:message', async (req, res) => {
    console.log('req.params:', req.params);
    const { message } = req.params;
    console.log('message:', message);
    const m = BigInt(message);
    console.log('m:', m);
    const keyPair = await keysPromise;
    console.log("privateKey:", keyPair.privateKey);
    const blindedSignature = keyPair.privateKey.sign(m);
    console.log('blindedSignature:', blindedSignature);
    res.json({ blindedSignature: blindedSignature.toString() });
});
app.post('/messageToUnpaillier/:message', async (req, res) => {
    console.log('req.params:', req.params);
    const { message } = req.params;
    console.log('message:', message);
    const keysPaillier = await paillierKeysPromise;
    const encryptedMul = BigInt(message);
    const messagefinal = keysPaillier.privateKey.decrypt(encryptedMul);
    console.log('messagefinal:', messagefinal);
    res.json({ messagefinal: messagefinal.toString() });
});
function generateCoefficients(threshold) {
    const coefficients = [];
    for (let i = 0; i < threshold - 1; i++) {
        // Generate a random coefficient and add it to the array
        const coefficient = Math.floor(Math.random() * 100); // Adjust the range as needed
        coefficients.push(coefficient);
    }
    return coefficients;
}
//Shamir
app.post('/shamir/:message/:threshold/:totalshares', async (req, res) => {
    console.log('req.params:', req.params);
    const { message } = req.params;
    const { threshold } = req.params;
    const { totalshares } = req.params;
    console.log('message:', message);
    console.log('threshold:', threshold);
    console.log('totalshares:', totalshares);
    const INTthreshold = parseInt(threshold);
    console.log('INTthreshold:', INTthreshold);
    const INTtotalshares = parseInt(totalshares);
    console.log('INTtotalshares:', INTtotalshares);
    const coefficients = generateCoefficients(INTthreshold);
    const shares = [];
    for (let i = 1; i <= INTtotalshares; i++) {
        const x = i; // Share index
        let y = parseInt(message);
        for (let j = 0; j < INTthreshold - 1; j++) {
            const power = Math.pow(x, j + 1);
            const term = coefficients[j] * power;
            y += term;
        }
        shares.push({ x, y });
    }
    return res.status(200).json(shares);
});
app.post('/reconstruct', async (req, res) => {
    const { shares } = req.body;
    console.log('shares:', shares);
    // Check if there are enough shares
    const threshold = shares[0].threshold;
    if (shares.length < threshold) {
        return res.status(400).json({ error: 'Insufficient shares to reconstruct the secret' });
    }
    // Extract x and y values from shares
    const xValues = shares.map((share) => share.x);
    const yValues = shares.map((share) => share.y);
    // Reconstruct the secret using Lagrange interpolation
    const secret = lagrangeInterpolation(xValues, yValues);
    return res.status(200).json({ secret });
});
function lagrangeInterpolation(xValues, yValues) {
    const n = xValues.length;
    let result = 0;
    for (let i = 0; i < n; i++) {
        let term = yValues[i];
        for (let j = 0; j < n; j++) {
            if (i !== j) {
                term *= (0 - xValues[j]) / (xValues[i] - xValues[j]);
            }
        }
        result += term;
    }
    return result;
}
/*function createShares(secret: number, threshold: number, totalShares: number): { x: number, y: number }[] {
  const coefficients = generateCoefficients(threshold);
  const shares: { x: number, y: number }[] = [];
  for (let i = 1; i <= totalShares; i++) {
    const x = i; // Share index
    let y = secret;
    for (let j = 0; j < threshold - 1; j++) {
      const power = Math.pow(x, j + 1);
      const term = coefficients[j] * power;
      y += term;
    }
    shares.push({ x, y });
  }
  return shares;
}*/
app.listen(port, () => {
    console.log(`listening on port ${port}`);
});
