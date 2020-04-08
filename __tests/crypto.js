/*
* Orwell http://github.com/gettocat/orwell
* Platform for building decentralized applications
* MIT License
* Copyright (c) 2017 Nanocat <@orwellcat at twitter>
*/

let crypto = function (privk, public) {
    this.ec = new EC('secp256k1');
    if (privk)
        this.private = this.ec.keyFromPrivate(privk, 16);

    if (!public && this.private)
        this.public = this.private.getPublic(true, 'hex');
    else if (public && this.private)
        this.public = public;
}

crypto.prototype = {
    ec: null,
    init: function () {


        if (!this.private) {
            this.private = this.ec.genKeyPair();
            this.public = this.private.getPublic(true);
            return 1;
        }


    },
    ecdsa: function () {
        return this.ec;
    }

}

const EC = require('elliptic').ec;
const ec = new EC('secp256k1')
const cr = require('crypto');
const hash = require('hash.js');
const base58 = require('base-58');
const merkle = require('merkle-tools')

module.exports = address = {
    createKeyPair: function () {
        var privateKey, publicKey;
        var cf = new crypto();
        if (status = cf.init()) {
            privateKey = cf.private.priv.toJSON();
            publicKey = cf.private.getPublic(true, 'hex');
        }

        return {
            status: status,
            public: publicKey,
            private: privateKey
        }
    },
    getPublicByPrivate: function (priv) {
        var cf = new crypto(priv);
        return cf.private.getPublic(true, 'hex');
    },
    sign: function (priv, messageBinary) {
        var cf = new crypto(priv),
            sig = cf.ecdsa().sign(messageBinary, new Buffer(priv, 'hex'))

        return new Buffer(sig.toDER())
    },
    verify: function (public, sign, messageBinary) {
        var key = ec.keyFromPublic(public, 'hex');
        return key.verify(messageBinary, sign, 'hex')
    },
    sha256: function (message, output) {
        if (!output)
            output = '';
        return cr.createHash('sha256').update(message).digest(output);
    },
    ripemd160: function (message, output) {
        if (!output)
            output = '';
        return hash.ripemd160().update(message).digest(output)
    },
    createAddressHashFromPublicKey: (pubkeyBuffOrHex) => {
        return address.ripemd160(address.sha256(new Buffer(pubkeyBuffOrHex, 'hex')), 'hex');
    },
    generateAddressFromPublicKey: (pubkeyBuffOrHex) => {
        let byte = Number('0').toString(16);
        if (byte.length < 2)
            byte = "0" + byte;
        let key = byte + address.createAddressHashFromPublicKey(pubkeyBuffOrHex);
        let f = address.sha256(address.sha256(new Buffer(key, 'hex')));

        let a = [];
        let buffer = f;
        for (let i = 0; i < 4; i++) {
            a.push(buffer[i]);
        }

        let dig = new Buffer(a).toString('hex');
        let res = key + dig;

        return base58.encode(new Buffer(res, 'hex'));
    },
    generateAddressFromAddrHash: (hash) => {

        let byte = Number('0').toString(16);
        if (byte.length < 2)
            byte = "0" + byte;
        var key = byte + hash;
        var f = address.sha256(address.sha256(new Buffer(key, 'hex')));

        var a = [];
        var buffer = f;
        for (var i = 0; i < 4; i++) {
            a.push(buffer[i]);
        }

        var dig = new Buffer(a).toString('hex');
        var res = key + dig;

        return base58.encode(new Buffer(res, 'hex'));
    },
    getPublicKeyHashByAddress: (addr) => {
        var key = new Buffer(base58.decode(addr));
        var buff = Buffer.alloc(20);
        for (var i = 0, k = 0; i < key.length; i++) {
            if (i == 0)
                continue;
            if (key.length - i <= 4)
                continue;

            buff[k++] = key[i];
        }

        return buff;
    },
    merkle(list) {

        function reverseBuffer(buff) {
            var out_rev = Buffer.alloc(buff.length), i = 0
            for (; i < buff.length; i++) {
                out_rev[buff.length - 1 - i] = buff[i];
            }

            return out_rev;
        }

        function makeMerkle(arr) {
            let m = new merkle()
            for (let i in arr) {
                m.addLeaf(reverseBuffer(new Buffer(arr[i].replace('0x', ''), 'hex')).toString('hex'))
            }

            m.makeBTCTree(true);
            return reverseBuffer(new Buffer(m.getMerkleRoot(), 'hex')).toString('hex')
        }

        return makeMerkle(list);
    }
}