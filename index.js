"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
exports.addPaillier = exports.decryptPaillier = exports.encryptPaillier = exports.generatePaillierKeys = exports.generateMyRsaKeys = exports.MyRsaPublicKey = void 0;
var bcu = require("bigint-crypto-utils");
var paillier = require("paillier-bigint");
var bc = require("bigint-conversion");
var MyRsaPublicKey = /** @class */ (function () {
    function MyRsaPublicKey(e, n) {
        this.e = e;
        this.n = n;
    }
    MyRsaPublicKey.prototype.encrypt = function (m) {
        var c = bcu.modPow(m, this.e, this.n);
        return c;
    };
    MyRsaPublicKey.prototype.verify = function (s) {
        var m = bcu.modPow(s, this.e, this.n);
        return m;
    };
    MyRsaPublicKey.prototype.toJSON = function () {
        return {
            e: bc.bigintToBase64(this.e),
            n: bc.bigintToBase64(this.n)
        };
    };
    MyRsaPublicKey.fromJSON = function (jsonKey) {
        var e = bc.base64ToBigint(jsonKey.e);
        var n = bc.base64ToBigint(jsonKey.n);
        return new MyRsaPublicKey(e, n);
    };
    return MyRsaPublicKey;
}());
exports.MyRsaPublicKey = MyRsaPublicKey;
var MyRsaPrivateKey = /** @class */ (function () {
    function MyRsaPrivateKey(d, n) {
        this.d = d;
        this.n = n;
    }
    MyRsaPrivateKey.prototype.decrypt = function (c) {
        var m = bcu.modPow(c, this.d, this.n);
        return m;
    };
    MyRsaPrivateKey.prototype.sign = function (m) {
        var s = bcu.modPow(m, this.d, this.n);
        return s;
    };
    MyRsaPrivateKey.prototype.toJSON = function () {
        return {
            d: bc.bigintToBase64(this.d),
            n: bc.bigintToBase64(this.n)
        };
    };
    MyRsaPrivateKey.fromJSON = function (jsonKey) {
        var d = bc.base64ToBigint(jsonKey.d);
        var n = bc.base64ToBigint(jsonKey.n);
        return new MyRsaPublicKey(d, n);
    };
    return MyRsaPrivateKey;
}());
function generateMyRsaKeys(bitlength) {
    return __awaiter(this, void 0, void 0, function () {
        var p, q, n, phi, e, d;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, bcu.prime(Math.floor(bitlength / 2))];
                case 1:
                    p = _a.sent();
                    return [4 /*yield*/, bcu.prime(Math.floor(bitlength / 2) + 1)];
                case 2:
                    q = _a.sent();
                    n = p * q;
                    phi = (p - 1n) * (q - 1n);
                    e = 65537n;
                    return [4 /*yield*/, bcu.modInv(e, phi)];
                case 3:
                    d = _a.sent();
                    return [2 /*return*/, {
                            publicKey: new MyRsaPublicKey(e, n),
                            privateKey: new MyRsaPrivateKey(d, n)
                        }];
            }
        });
    });
}
exports.generateMyRsaKeys = generateMyRsaKeys;
function generatePaillierKeys(bitlength) {
    return __awaiter(this, void 0, void 0, function () {
        var keys;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, paillier.generateRandomKeysSync(bitlength)];
                case 1:
                    keys = _a.sent();
                    return [2 /*return*/, {
                            publicKey: keys.publicKey,
                            privateKey: keys.privateKey
                        }];
            }
        });
    });
}
exports.generatePaillierKeys = generatePaillierKeys;
function encryptPaillier(m, publicKey) {
    return __awaiter(this, void 0, void 0, function () {
        var c;
        return __generator(this, function (_a) {
            c = publicKey.encrypt(m);
            return [2 /*return*/, c];
        });
    });
}
exports.encryptPaillier = encryptPaillier;
function decryptPaillier(c, publicKey, privateKey) {
    return __awaiter(this, void 0, void 0, function () {
        var m;
        return __generator(this, function (_a) {
            m = privateKey.decrypt(c);
            return [2 /*return*/, m];
        });
    });
}
exports.decryptPaillier = decryptPaillier;
function addPaillier(c1, c2, publicKey) {
    return __awaiter(this, void 0, void 0, function () {
        var c;
        return __generator(this, function (_a) {
            c = publicKey.addition(c1, c2);
            return [2 /*return*/, c];
        });
    });
}
exports.addPaillier = addPaillier;
