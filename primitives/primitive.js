const { EventEmitter } = require('events');

class Primitive extends EventEmitter {
    constructor() {
        super();
    }
    throwError(message, code) {
        throw new Error(message, code)
    }
    getAddressByPublicKey(publicKeyHex) {
        throw new Error('PRIMITIVE::getAddressByPublicKey must be implemented');
    }
    getPublicKeyByPrivateKey(privateKeyHex) {
        throw new Error('PRIMITIVE::getPublicKeyByPrivateKey must be implemented');
    }
    getBlockValue(fee, height) {
        throw new Error('PRIMITIVE::getBlockValue must be implemented');
    }
    isValidAddress(address) {
        throw new Error('PRIMITIVE::isValidAddress must be implemented');
    }
    addressToHexValue(address) {
        throw new Error('PRIMITIVE::addressToHexValue must be implemented');
    }
    hexValueToAddress(hex) {
        throw new Error('PRIMITIVE::hexValueToAddress must be implemented');
    }
    createHash(binaryOrHex) {
        throw new Error('PRIMITIVE::hash must be implemented');
    }
    sign(privateKeyBinary, hash) {
        throw new Error('PRIMITIVE::sign must be implemented');
    }
    verify(pubkey, sign, hash2sign) {
        throw new Error('PRIMITIVE::verify must be implemented');
    }
    getOut(hash, index) {
        throw new Error('PRIMITIVE::getOut must be implemented');
    }
    getMerkleRoot(list) {
        throw new Error('PRIMITIVE::getMerkleRoot must be implemented');
    }
    getMemPool() {
        throw new Error('PRIMITIVE::getMemPool must be implemented');
    }
    getTop() {
        throw new Error('PRIMITIVE::getTop must be implemented');
    }
    getCurrentTime() {
        return parseInt(Date.now() / 1000)
    }
    createMerkle(list){
        throw new Error('PRIMITIVE::createMerkle must be implemented');
    }
    createCoinbaseOutputs(privateKey, fullamount, validators) {
        let currnode = this.getPublicKeyByPrivateKey(privateKey);
        let outs = [

        ];

        let lessamount = fullamount * .05;
        for (let i in validators) {
            let am = lessamount / (validators.length - 1);
            if (validators[i] == currnode)
                am = fullamount * .95;

            outs.push({
                key: validators[i],
                address: this.getAddressByPublicKey(validators[i]),
                amount: am
            });

        }

        return outs;
    }
}

module.exports = Primitive;