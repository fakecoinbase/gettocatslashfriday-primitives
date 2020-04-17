const APP = require('../index');
const tools = require('./crypto');

let app = new APP({
    validationalert: true,//throw exception on each validation error if true, false - execute and write to validator log
    genesisMode: false,
    blockversion: 1,
    txversion: 1
});

app.definePrimitive((() => {
    class Privitive2 extends app.PRIMITIVE {//must extends from app.PRIMITIVE class, and redefine it here
        constructor() {
            super();
        }
        throwError(message, code) {
            throw new Error(message, code)
        }
        getAddressByPublicKey(publicKeyHex) {
            return tools.generateAddressFromPublicKey(publicKeyHex);
        }
        getPublicKeyByPrivateKey(privateKeyHex) {
            return tools.getPublicByPrivate(privateKeyHex);
        }
        getBlockValue(fee, height) {
            return fee + height;
        }
        isValidAddress(address) {
            return true;
        }
        addressToHexValue(address) {
            return tools.getPublicKeyHashByAddress(address).toString('hex')
        }
        hexValueToAddress(hex) {
            return tools.generateAddressFromAddrHash(hex);
        }
        createHash(binaryOrHex) {
            return tools.sha256(binaryOrHex, 'hex');
        }
        sign(privateKeyBinaryOrHex, hash) {
            return tools.sign(new Buffer(privateKeyBinaryOrHex, 'hex'), hash);
        }
        verify(pubkey, sign, hash2sign) {
            return tools.verify(pubkey, sign, new Buffer(hash2sign, 'hex'));
        }
        getOut(hash, index) {
            return 0;
        }
        getMerkleRoot(list) {
            return tools.merkle(list);
        }
        getMemPool() {
            return [];
        }
        getTop() {
            return { height: -1, id: '0000000000000000000000000000000000000000000000000000000000000000' }
        }
        createMerkle(list){
            return tools.merkle(list)
        }
    }

    return Privitive2;
})(app))

let tx = app.Transaction;
let block = app.Block;

tx.VALIDATOR.addRule('test', (validator) => {//context - tx object, validator - first param
    if (this.v != 0) {
        //validator.addError('log message, for debug', 1);
        return false;
    }
    return true;
})

/*
{ status: 1,
  public:
   '03d91664779705d9184741d6ce98812171daf3b0350d208d2615f3e017adf11a16',
  private:
   '6e393b0abedbadf29e838ed7ae48c027b30b4d257903a1b5bcb544a19bde9ec6' }
*/

//create from json
/*let keystore = tools.createKeyPair();
console.log(keystore);
let tx1 = tx.createFromJSON({
    v: 1,
    in: [
        { hash: tools.sha256('1', 'hex'), index: 0 }
    ],
    out: [
        { address: tools.generateAddressFromPublicKey(keystore.public), amount: 1e9 }
    ]
}, [keystore.private]);
console.log(tx1.toJSON());*/

//json->hex
/*
let json = {
    v: 1,
    s:
        [
            ['30450221009e9458173ce598788299be8ace0df9e327fbacdeb84038d06874ec8ae2f510d30220103cfe4d9708e246854a287c0cb4865b479ac094281faa7f5fd81bbf6464c182',
                '03d91664779705d9184741d6ce98812171daf3b0350d208d2615f3e017adf11a16']
        ],
    in:
        [{
            hash:
                '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            index: 0
        }],
    out:
        [{
            address: '14aBx8Y7AYhjVM6eh7wt1nmqqhUUi8CbGs',
            amount: 1000000000
        }]
};

//hex:
//01001d2dbe6f050004020176010601730106000204008e333034353032323130303965393435383137336365353938373838323939626538616365306466396533323766626163646562383430333864303638373465633861653266353130643330323230313033636665346439373038653234363835346132383763306362343836356234373961633039343238316661613766356664383162626636343634633138320400423033643931363634373739373035643931383437343164366365393838313231373164616633623033353064323038643236313566336530313761646631316131360602696e0105000204046861736840366238366232373366663334666365313964366238303465666635613366353734376164613465616132326631643439633031653532646462373837356234620205696e6465780006036f7574010500020407616464726573732231346142783859374159686a564d366568377774316e6d71716855556938436247730206616d6f756e74ff00ca9a3b00000000
//id: cffd81c5848e5a35a669aa0fd89030e2525fccb7c864e2a036ec1aa94f2402ac

let tx2 = tx.fromJSON(json);
console.log(tx2.getId(), tx2.toJSON(), tx2.toHex());*/

//tx hex->json
//let tx3 = tx.fromHEX('01001d2dbe6f050004020176010601730106000204008e333034353032323130303965393435383137336365353938373838323939626538616365306466396533323766626163646562383430333864303638373465633861653266353130643330323230313033636665346439373038653234363835346132383763306362343836356234373961633039343238316661613766356664383162626636343634633138320400423033643931363634373739373035643931383437343164366365393838313231373164616633623033353064323038643236313566336530313761646631316131360602696e0105000204046861736840366238366232373366663334666365313964366238303465666635613366353734376164613465616132326631643439633031653532646462373837356234620205696e6465780006036f7574010500020407616464726573732231346142783859374159686a564d366568377774316e6d71716855556938436247730206616d6f756e74ff00ca9a3b00000000');
//console.log(tx3.getId(), tx3.toJSON());

//tx build coinbase
//let coinbase = tx.createCoinbase(0.01, "001133", "6e393b0abedbadf29e838ed7ae48c027b30b4d257903a1b5bcb544a19bde9ec6", tools.merkle(["11", "22", "33"]), 0);
//console.log(coinbase.toJSON());

//big tx check:
//2 input 3 outputs

let keystore1 = tools.createKeyPair();
let keystore2 = tools.createKeyPair();
let keystore3 = tools.createKeyPair();
let keystore4 = tools.createKeyPair();

//console.log(keystore1, keystore2, keystore3, keystore4);
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


//let tx6 = tx.fromHEX(tx5.toHex());
//console.log(tx5.toJSON(), tx5.toHex(), tx6.toJSON(), tx6.toHex());

//tx check verify - ok
//console.log(tx6.isValid());

block.VALIDATOR.addRule('test', (validator) => {//context - tx object, validator - first param
    let block = validator.block;//this must be block context, but {} ??? TODO: fix this.
    console.log('validator exec', block.prev, block.prev == '0000000000000000000000000000000000000000000000000000000000000000');
    
    if (block.prev == '0000000000000000000000000000000000000000000000000000000000000000') {
        validator.addError('prev is invalid', -1);
        return false;
    }
    return true;
})

//block create new
let keystore = tools.createKeyPair();
let b = block.createNewBlock("001122", keystore, ['00', '11', '22']);
b.addTx(tx5);

let b2 = block.fromHEX(b.toHex());
console.log(JSON.stringify(b2.toJSON()),'\n\n\n', JSON.stringify(b.toJSON()));

//block json->hex
//block hex->json
//block build
//block verify check
let res = b.isValid();
