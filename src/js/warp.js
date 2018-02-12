const {scrypt,pbkdf2,HMAC_SHA256,WordArray,util}  = require('triplesec')
const blake = require('blakejs');
const nacl = require('tweetnacl/nacl');
const params = require('../json/params.json')

//=====================================

const from_utf8 = function(s, i) {
  const b = new Buffer(s, 'utf8')
  const b2 = Buffer.concat([ b, (new Buffer([ i ])) ])
  const ret = WordArray.from_buffer(b2)
  util.scrub_buffer(b)
  util.scrub_buffer(b2)
  return ret
}

function dec2hex(str, bytes = null) {
    let dec = str.toString().split(''), sum = [], hex = [], i, s
    while(dec.length)
    {
        s = 1 * dec.shift()
        for(i = 0; s || i < sum.length; i++)
        {
            s += (sum[i] || 0) * 10
            sum[i] = s % 16
            s = (s - sum[i]) / 16
        }
    }
    while(sum.length)
    {
        hex.push(sum.pop().toString(16));
    }

    hex = hex.join('');

    if(hex.length % 2 !== 0)
        hex = "0" + hex;

    if(bytes > hex.length / 2)
    {
        let diff = bytes - hex.length / 2;
        for(let i = 0; i < diff; i++)
            hex = "00" + hex;
    }

    return hex;
}

// Arrays manipulations
function uint8_uint4 (uint8) {
    let length = uint8.length;
    let uint4 = new Uint8Array(length*2);
    for (let i = 0; i < length; i++) {
        uint4[i*2] = uint8[i] / 16 | 0;
        uint4[i*2+1] = uint8[i] % 16;
    }
    return uint4;
}

function uint4_uint8 (uint4) {
    let length = uint4.length / 2;
    let uint8 = new Uint8Array(length);
    for (let i = 0; i < length; i++)	uint8[i] = uint4[i*2] * 16 + uint4[i*2+1];
    return uint8;
}

function uint4_uint5 (uint4) {
    let length = uint4.length / 5 * 4;
    let uint5 = new Uint8Array(length);
    for (let i = 1; i <= length; i++) {
        let n = i - 1;
        let m = i % 4;
        let z = n + ((i - m)/4);
        let right = uint4[z] << m;
        let left;
        if (((length - i) % 4) === 0)	left = uint4[z-1] << 4;
        else	left = uint4[z+1] >> (4 - m);
        uint5[n] = (left + right) % 32;
    }
    return uint5;
}

function uint5_uint4 (uint5) {
    let length = uint5.length / 4 * 5;
    let uint4 = new Uint8Array(length);
    for (let i = 1; i <= length; i++) {
        let n = i - 1;
        let m = i % 5;
        let z = n - ((i - m)/5);
        let right = uint5[z-1] << (5 - m);
        let left = uint5[z] >> m;
        uint4[n] = (left + right) % 16;
    }
    return uint4;
}

function string_uint5 (string) {
    let letter_list = letter_list = '13456789abcdefghijkmnopqrstuwxyz'.split('');
    let length = string.length;
    let string_array = string.split('');
    let uint5 = new Uint8Array(length);
    for (let i = 0; i < length; i++)	uint5[i] = letter_list.indexOf(string_array[i]);
    return uint5;
}

function uint5_string (uint5) {
    let letter_list = letter_list = '13456789abcdefghijkmnopqrstuwxyz'.split('');
    let string = "";
    for (let i = 0; i < uint5.length; i++)	string += letter_list[uint5[i]];
    return string;
}

function hex_uint8 (hex) {
    let length = (hex.length / 2) | 0;
    let uint8 = new Uint8Array(length);
    for (let i = 0; i < length; i++) uint8[i] = parseInt(hex.substr(i * 2, 2), 16);
    return uint8;
}

function hex_uint4 (hex) {
    let length = hex.length;
    let uint4 = new Uint8Array(length);
    for (let i = 0; i < length; i++) uint4[i] = parseInt(hex.substr(i, 1), 16);
    return uint4;
}

function uint8_hex (uint8) {
    let hex = "";
    let aux = null;
    for (let i = 0; i < uint8.length; i++)
    {
        aux = uint8[i].toString(16).toUpperCase();
        if(aux.length === 1)
            aux = '0'+aux;
        hex += aux;
        aux = '';
    }
    return(hex);
}

function uint4_hex (uint4) {
    var hex = "";
    for (let i = 0; i < uint4.length; i++) hex += uint4[i].toString(16).toUpperCase();
    return(hex);
}

function equal_arrays (array1, array2) {
    for (let i = 0; i < array1.length; i++) {
        if (array1[i] != array2[i])	return false;
    }
    return true;
}

function array_crop (array) {
    var length = array.length - 1;
    var cropped_array = new Uint8Array(length);
    for (let i = 0; i < length; i++)
        cropped_array[i] = array[i+1];
    return cropped_array;
}

function deriveAddress(hex) {
    let key_bytes = uint4_uint8( hex_uint4 (hex) );
    let checksum = uint5_string( uint4_uint5( uint8_uint4( blake.blake2b(key_bytes, null, 5).reverse() ) ) );
    let c_account = uint5_string( uint4_uint5( hex_uint4 ('0' + hex) ) );
    return 'xrb_' + c_account + checksum;
}

function deriveKeypair (seed) {
  let index = hex_uint8(dec2hex(0, 4));
  let ctx = blake.blake2bInit(32);
  blake.blake2bUpdate(ctx, hex_uint8(seed));
  blake.blake2bUpdate(ctx, index);
  let prv = blake.blake2bFinal(ctx);

  return {
    publicKey: uint8_hex(nacl.sign.keyPair.fromSecretKey(prv).publicKey),
    privateKey: uint8_hex(prv)
  }
}

module.exports = async function({passphrase, salt, progress_hook}, cb) {
  const scrypt_params = { 
    N             : params.N,
    p             : params.p,
    r             : params.r,
    dkLen         : params.dkLen,
    pbkdf2c       : params.pbkdf2c,
    key           : from_utf8(passphrase, 1),
    salt          : from_utf8(salt, 1),
    progress_hook : progress_hook
  }

  let s1 = await new Promise((res,rej) => scrypt(scrypt_params, res))

  const pbkdf2_params = {
    key           : from_utf8(passphrase, 2),
    salt          : from_utf8(salt, 2),
    c             : params.pbkdf2c,
    dkLen         : params.dkLen,
    progress_hook : progress_hook,
    klass         : HMAC_SHA256
  }

  let s2 = await new Promise((res,rej) => pbkdf2(pbkdf2_params, res))

  s1.xor(s2,{})

  const seed_hex = s1.to_hex().toUpperCase()

  let garbage = [s1, s2, scrypt_params.key, pbkdf2_params.key]
  garbage.forEach(obj => obj.scrub())

  let out = deriveKeypair(seed_hex)
  out.seed = seed_hex;
  out.address = deriveAddress(out.publicKey)
  cb(out)
}