const APP = require('./index');
const tools = require('./__tests/crypto');

let app = new APP({
    validationalert: true,//throw exception on each validation error if true, false - execute and write to validator log
    genesisMode: false, // genesisMode makes first block
    blockversion: 1,//block version
    txversion: 1//transaction verion
});

app.definePrimitive((() => {//Primitive - abstract class with important methods, must be reimplemented!
    class Privitive2 extends app.PRIMITIVE {//must extends from app.PRIMITIVE class, and redefine it here
        constructor() {
            super();
        }
        throwError(message, code) {//throw error
            throw new Error(message, code)
        }
        getAddressByPublicKey(publicKeyHex) {//create address from public key ec
            return tools.generateAddressFromPublicKey(publicKeyHex);
        }
        getPublicKeyByPrivateKey(privateKeyHex) {//get public key by privatekey
            return tools.getPublicByPrivate(privateKeyHex);
        }
        getBlockValue(fee, height) {//get block value by height and fee
            return fee + height;
        }
        isValidAddress(address) {//address is valid
            return true;
        }
        addressToHexValue(address) {//get hash by address value / im think is not important (not used yet)
            return tools.getPublicKeyHashByAddress(address).toString('hex')
        }
        hexValueToAddress(hex) {//back, hash -> address
            return tools.generateAddressFromAddrHash(hex);
        }
        createHash(binaryOrHex) {//hash method
            return tools.sha256(binaryOrHex, 'hex');
        }
        sign(privateKeyBinaryOrHex, hash) {//sign msg by private key
            return tools.sign(new Buffer(privateKeyBinaryOrHex, 'hex'), hash);
        }
        verify(pubkey, sign, hash2sign) {//verify sign of message(hash2sign) with pubkey
            return tools.verify(pubkey, sign, new Buffer(hash2sign, 'hex'));
        }
        getOut(hash, index) {//get prev out amount
            return 0;
        }
        getMerkleRoot(list) {//merkle root algorithm
            return tools.merkle(list);
        }
        getMemPool() {//mempool list
            return [];
        }
        getTop() {//get top info (last block and curr height)
            return { height: -1, id: '0000000000000000000000000000000000000000000000000000000000000000' }
        }
    }

    return Privitive2;
})(app));

app.defineTx((() => {
    class Tx2 extends app.TX {
        constructor() {
            super();
        }
        //TX::send must be reimplemented   
        checkVersion() {
            return 2;
        }
    }

    return Tx2;
})(app));

app.defineBlock((() => {
    class Block2 extends app.BLOCK {
        constructor() {
            super();
        }
        //BLOCK::send must be reimplemented
        checkVersion() {
            return 2;
        }
    }

    return Block2;
})(app));

let tx = app.Transaction;
let block = app.Block;

//tx
//build
let keystore = tools.createKeyPair();
let tx1 = tx.createFromJSON({
    v: 1,
    in: [
        { hash: tools.sha256('1', 'hex'), index: 0 }
    ],
    out: [
        { address: tools.generateAddressFromPublicKey(keystore.public), amount: 1e9 }
    ]
}, [keystore.private]);

//console.log('extending',tx1.checkVersion());
console.log('build tx', tx1.toJSON());

//build coinbase
let coinbase = tx.createCoinbase(0.01, "001133", "6e393b0abedbadf29e838ed7ae48c027b30b4d257903a1b5bcb544a19bde9ec6", tools.merkle(["11", "22", "33"]), 0);
console.log('build coinbase', coinbase.toJSON());

//to json/from json
//to hex/from hex
let keystore1 = {
    status: 1,
    public:
        '0273d5300e1401b4e84aebdb50923715d15d762779e7c74edbcd7299c534ae3bb5',
    private:
        '603a446f91f0065cf2fcdfb0967cec49e974db10187d027e79ecc1489ec73c49'
};

let keystore2 = {
    status: 1,
    public:
        '0255264eb87b09758c2f0fdd6e646a0d7d85e5084371b1f442be0d5026d02e8ed0',
    private:
        'c23b263b08cecd64de76191f5e4af1b6a7b1413ef9e1052234441c1769bc880d'
};
let keystore3 = {
    status: 1,
    public:
        '02ecc65bbf5e269d08c16cc289dbb66c75a1f645d0e65570cce168f6bb3b7ef463',
    private:
        '1555c17c8d0b3a351a0b4e992b458793ed8f4fbf05dcb79bc1b81ff08d323732'
};
let keystore4 = {
    status: 1,
    public:
        '0281af05d6f2c162a01a5326bad229f60f7fc39e0f98b32ce4f1ccb3d046a57e91',
    private:
        '10730110c182f8f486698b0d6bc5199b66801123f0858db1215fb9a8da851cfa'
}

let tx5 = tx.createFromJSON({
    v: 1,
    in: [
        { hash: tools.sha256('1', 'hex'), index: 0 },
        { hash: tools.sha256('2', 'hex'), index: 120 },
        { hash: tools.sha256('3', 'hex'), index: 4521 },
        { hash: tools.sha256('4', 'hex'), index: 0 },
    ],
    out: [
        { address: tools.generateAddressFromPublicKey(keystore1.public), amount: 1e9 },
        { address: tools.generateAddressFromPublicKey(keystore2.public), amount: 13e9 },
        { address: tools.generateAddressFromPublicKey(keystore3.public), amount: 5e9 },
    ]
}, [keystore1.private, keystore2.private, keystore3.private, keystore4.private]);

let tx6 = tx.fromHEX(tx5.toHex());
console.log('tohex/fromhex', JSON.stringify(tx5.toJSON()) == JSON.stringify(tx6.toJSON()));


let tx7 = tx.fromJSON(tx5.toJSON());
console.log('tojson/fromjson', tx7.toHex() == tx5.toHex());

//validation
tx.VALIDATOR.addRule('testvalidation', (validator) => {//context - tx object, validator - first param
    if (validator.tx.inputs.length != 0) {
        //validator.addError('log message, for debug', 1);
        return false;
    }
    return true;
})
let tx8 = tx.fromJSON(tx7.toJSON());
console.log('validation must be false: ', tx8.isValid());


//block
//build
let keystore5 = {
    status: 1,
    public:
        '02ecc65bbf5e269d08c16cc289dbb66c75a1f645d0e65570cce168f6bb3b7ef463',
    private:
        '1555c17c8d0b3a351a0b4e992b458793ed8f4fbf05dcb79bc1b81ff08d323732'
};
let b = block.createNewBlock("001122", keystore5, tools.merkle(['00', '11', '22']));
b.addTx(tx8);

//to json/from json
//to hex/from hex
let b2 = block.fromHEX(b.toHex());
console.log('block json/hex', JSON.stringify(b2.toJSON()) == JSON.stringify(b.toJSON()));

block.VALIDATOR.addRule('test', (validator) => {//context - tx object, validator - first param
    let block = validator.block;//this must be block context, but {} ??? TODO: fix this.
    if (block.prev == '0000000000000000000000000000000000000000000000000000000000000000') {
        validator.addError('prev is invalid', -1);
        return false;
    }
    return true;
})

//validation
try {
    console.log('block validation must be false (but throw exception): ', b.isValid());
} catch (e) {
    console.log('block validation must throw exception', e);
}