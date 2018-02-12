'use strict';

var _regenerator = require('babel-runtime/regenerator');

var _regenerator2 = _interopRequireDefault(_regenerator);

var _promise = require('babel-runtime/core-js/promise');

var _promise2 = _interopRequireDefault(_promise);

var _asyncToGenerator2 = require('babel-runtime/helpers/asyncToGenerator');

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var _require = require('triplesec'),
    scrypt = _require.scrypt,
    pbkdf2 = _require.pbkdf2,
    HMAC_SHA256 = _require.HMAC_SHA256,
    WordArray = _require.WordArray,
    util = _require.util;

var blake = require('blakejs');
var nacl = require('tweetnacl/nacl');
var params = require('../json/params.json');

//=====================================

var from_utf8 = function from_utf8(s, i) {
    var b = new Buffer(s, 'utf8');
    var b2 = Buffer.concat([b, new Buffer([i])]);
    var ret = WordArray.from_buffer(b2);
    util.scrub_buffer(b);
    util.scrub_buffer(b2);
    return ret;
};

function dec2hex(str) {
    var bytes = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : null;

    var dec = str.toString().split(''),
        sum = [],
        hex = [],
        i = void 0,
        s = void 0;
    while (dec.length) {
        s = 1 * dec.shift();
        for (i = 0; s || i < sum.length; i++) {
            s += (sum[i] || 0) * 10;
            sum[i] = s % 16;
            s = (s - sum[i]) / 16;
        }
    }
    while (sum.length) {
        hex.push(sum.pop().toString(16));
    }

    hex = hex.join('');

    if (hex.length % 2 !== 0) hex = "0" + hex;

    if (bytes > hex.length / 2) {
        var diff = bytes - hex.length / 2;
        for (var _i = 0; _i < diff; _i++) {
            hex = "00" + hex;
        }
    }

    return hex;
}

// Arrays manipulations
function uint8_uint4(uint8) {
    var length = uint8.length;
    var uint4 = new Uint8Array(length * 2);
    for (var i = 0; i < length; i++) {
        uint4[i * 2] = uint8[i] / 16 | 0;
        uint4[i * 2 + 1] = uint8[i] % 16;
    }
    return uint4;
}

function uint4_uint8(uint4) {
    var length = uint4.length / 2;
    var uint8 = new Uint8Array(length);
    for (var i = 0; i < length; i++) {
        uint8[i] = uint4[i * 2] * 16 + uint4[i * 2 + 1];
    }return uint8;
}

function uint4_uint5(uint4) {
    var length = uint4.length / 5 * 4;
    var uint5 = new Uint8Array(length);
    for (var i = 1; i <= length; i++) {
        var n = i - 1;
        var m = i % 4;
        var z = n + (i - m) / 4;
        var right = uint4[z] << m;
        var left = void 0;
        if ((length - i) % 4 === 0) left = uint4[z - 1] << 4;else left = uint4[z + 1] >> 4 - m;
        uint5[n] = (left + right) % 32;
    }
    return uint5;
}

function uint5_uint4(uint5) {
    var length = uint5.length / 4 * 5;
    var uint4 = new Uint8Array(length);
    for (var i = 1; i <= length; i++) {
        var n = i - 1;
        var m = i % 5;
        var z = n - (i - m) / 5;
        var right = uint5[z - 1] << 5 - m;
        var left = uint5[z] >> m;
        uint4[n] = (left + right) % 16;
    }
    return uint4;
}

function string_uint5(string) {
    var letter_list = letter_list = '13456789abcdefghijkmnopqrstuwxyz'.split('');
    var length = string.length;
    var string_array = string.split('');
    var uint5 = new Uint8Array(length);
    for (var i = 0; i < length; i++) {
        uint5[i] = letter_list.indexOf(string_array[i]);
    }return uint5;
}

function uint5_string(uint5) {
    var letter_list = letter_list = '13456789abcdefghijkmnopqrstuwxyz'.split('');
    var string = "";
    for (var i = 0; i < uint5.length; i++) {
        string += letter_list[uint5[i]];
    }return string;
}

function hex_uint8(hex) {
    var length = hex.length / 2 | 0;
    var uint8 = new Uint8Array(length);
    for (var i = 0; i < length; i++) {
        uint8[i] = parseInt(hex.substr(i * 2, 2), 16);
    }return uint8;
}

function hex_uint4(hex) {
    var length = hex.length;
    var uint4 = new Uint8Array(length);
    for (var i = 0; i < length; i++) {
        uint4[i] = parseInt(hex.substr(i, 1), 16);
    }return uint4;
}

function uint8_hex(uint8) {
    var hex = "";
    var aux = null;
    for (var i = 0; i < uint8.length; i++) {
        aux = uint8[i].toString(16).toUpperCase();
        if (aux.length === 1) aux = '0' + aux;
        hex += aux;
        aux = '';
    }
    return hex;
}

function uint4_hex(uint4) {
    var hex = "";
    for (var i = 0; i < uint4.length; i++) {
        hex += uint4[i].toString(16).toUpperCase();
    }return hex;
}

function equal_arrays(array1, array2) {
    for (var i = 0; i < array1.length; i++) {
        if (array1[i] != array2[i]) return false;
    }
    return true;
}

function array_crop(array) {
    var length = array.length - 1;
    var cropped_array = new Uint8Array(length);
    for (var i = 0; i < length; i++) {
        cropped_array[i] = array[i + 1];
    }return cropped_array;
}

function deriveAddress(hex) {
    var key_bytes = uint4_uint8(hex_uint4(hex));
    var checksum = uint5_string(uint4_uint5(uint8_uint4(blake.blake2b(key_bytes, null, 5).reverse())));
    var c_account = uint5_string(uint4_uint5(hex_uint4('0' + hex)));
    return 'xrb_' + c_account + checksum;
}

function deriveKeypair(seed) {
    var index = hex_uint8(dec2hex(0, 4));
    var ctx = blake.blake2bInit(32);
    blake.blake2bUpdate(ctx, hex_uint8(seed));
    blake.blake2bUpdate(ctx, index);
    var prv = blake.blake2bFinal(ctx);

    return {
        publicKey: uint8_hex(nacl.sign.keyPair.fromSecretKey(prv).publicKey),
        privateKey: uint8_hex(prv)
    };
}

module.exports = function () {
    var _ref2 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee(_ref, cb) {
        var passphrase = _ref.passphrase,
            salt = _ref.salt,
            progress_hook = _ref.progress_hook;
        var scrypt_params, s1, pbkdf2_params, s2, seed_hex, garbage, out;
        return _regenerator2.default.wrap(function _callee$(_context) {
            while (1) {
                switch (_context.prev = _context.next) {
                    case 0:
                        scrypt_params = {
                            N: params.N,
                            p: params.p,
                            r: params.r,
                            dkLen: params.dkLen,
                            pbkdf2c: params.pbkdf2c,
                            key: from_utf8(passphrase, 1),
                            salt: from_utf8(salt, 1),
                            progress_hook: progress_hook
                        };
                        _context.next = 3;
                        return new _promise2.default(function (res, rej) {
                            return scrypt(scrypt_params, res);
                        });

                    case 3:
                        s1 = _context.sent;
                        pbkdf2_params = {
                            key: from_utf8(passphrase, 2),
                            salt: from_utf8(salt, 2),
                            c: params.pbkdf2c,
                            dkLen: params.dkLen,
                            progress_hook: progress_hook,
                            klass: HMAC_SHA256
                        };
                        _context.next = 7;
                        return new _promise2.default(function (res, rej) {
                            return pbkdf2(pbkdf2_params, res);
                        });

                    case 7:
                        s2 = _context.sent;


                        s1.xor(s2, {});

                        seed_hex = s1.to_hex().toUpperCase();
                        garbage = [s1, s2, scrypt_params.key, pbkdf2_params.key];

                        garbage.forEach(function (obj) {
                            return obj.scrub();
                        });

                        out = deriveKeypair(seed_hex);

                        out.seed = seed_hex;
                        out.address = deriveAddress(out.publicKey);
                        cb(out);

                    case 16:
                    case 'end':
                        return _context.stop();
                }
            }
        }, _callee, this);
    }));

    return function (_x2, _x3) {
        return _ref2.apply(this, arguments);
    };
}();
