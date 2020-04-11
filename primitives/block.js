const bitowl = require('bitowl');

module.exports = (app) => {

    class block extends app.PRIMITIVE {
        constructor(data) {
            super();
            this.type = 'build';

            this.version = app.config.blockversion;
            this.prev = '';
            this.merkle = '';
            this.time = 0;
            this.bits = 0;
            this.nonce = 0;
            this.index = 0;
            this.tx = [];

            this.hex = '';

            this.validation_errors = [];
            this.hash = null;

            if (data) {
                if (!(data instanceof Buffer || typeof data == 'string'))
                    throw new Error('Block:Constructor, data must be string (hex) or buffer instance');

                this.hex = new Buffer(data, 'hex');
                this.type = 'raw';
                this.init();
            }

        }
        init() {
            if (this.type == 'build') {
                //create hex
                this.hex = this.toBuffer();
            }

            if (this.type == 'raw') {
                //decode hex
                this.fromJSON(bitowl.data.unpack(this.hex))
            }

            if (this.type == 'json') {
                //create hex
                this.hex = this.toBuffer();
            }

            this.hash = this.getHash('hex');

            if (this.version > app.config.blockversion) {
                this.emit("unsupportedversion", app.config.blockversion, this.version);
            }//else is okay

        }
        addTxFromHEX(hex) {
            this.tx.push(new app.TX.fromHEX(hex));
            this.updateMerkle();
            return this;
        }
        addTxFromJSON(json) {
            this.tx.push(new app.TX.fromJSON(json));
            this.updateMerkle();
            return this;
        }
        addTx(tx) {
            if (!(tx instanceof app.TX || tx instanceof app.PRIMITIVE))
                this.throwError('Object is not TX', 'not_tx_obj');
            this.tx.push(tx);
            this.updateMerkle();
            return this;
        }
        addTxList(hexArr) {
            for (let i in hexArr) {
                if (hexArr[i] instanceof app.TX || tx instanceof app.PRIMITIVE)
                    this.tx.push(hexArr[i])
                else if ((typeof hexArr[i] === 'string' || hexArr[i] instanceof Buffer))
                    this.tx.push(app.TX.fromHEX(hexArr[i]));
                else if ((hexArr[i] instanceof Object))
                    this.tx.push(app.TX.fromJSON(hexArr[i]));
            }
            this.updateMerkle();
            return this;
        }
        updateMerkle() {
            let ids = [];
            for (let i in this.tx) {
                if (this.tx[i])
                    ids.push(this.tx[i].getId())
            }

            return this.merkle = this.getMerkleRoot(ids);
        }
        getHash(format) {
            //new block
            if (!this.hash || format == 'raw') {

                if (!this.merkle)
                    this.updateMerkle();

                let h = this.createHash(this.getHeaderBytes());

                if (format == 'hex' || !format)
                    return this.hash = h.toString('hex');
                else
                    return h;
            } else {
                return this.hash;
            }
        }
        getFee() {
            let a = 0;
            for (let i in this.tx) {
                a += this.tx[i].getFee();
            }

            return a;
        }
        getSize() {
            let a = 0;
            for (let i in this.tx) {
                a += this.tx[i].getSize();
            }

            let txsize = Math.ceil(tx.length.toString(16).length) / 2;//can be %2 != 0, first digit!
            a += getHeaderBytes().length + 5 + txsize;//bitowl notation - tx: [] 0102TTXX05(SIZEOFLENGTH) type|key(var_str)|value, value is array: value.length|value[0],...,value[n]

            return a;
        }
        getHeader() {
            return {
                v: this.version,
                p: this.prev,
                m: this.merkle ? this.merkle : this.updateMerkle(),
                t: this.time,
                b: this.bits,
                n: this.nonce
            }
        }
        getHeaderBytes() {
            return bitowl.data.pack(this.getHeader());
        }
        getHeaderHex() {
            return this.getHeaderBytes().toString('hex');
        }
        toHex() {
            return this.toBuffer().toString('hex');
        }
        toBuffer() {
            return bitowl.data.pack(this.toJSON());
        }
        fromHex(hex) {
            this.type = 'raw';
            this.hex = new Buffer(hex, 'hex');
            this.init();
            return this;
        }
        toJSON(rules) {
            if (!rules)
                rules = "";

            let o = {
                v: this.version,
                p: this.prev,
                m: this.merkle ? this.merkle : this.updateMerkle(),
                t: this.time,
                b: this.bits,
                n: this.nonce,
                tx: [
                ]
            }

            if (rules.split(",").indexOf('hash') != -1) {
                o.hash = this.getId();
            }

            for (let i in this.tx) {
                if (this.tx[i])
                    o.tx.push(this.tx[i].toJSON(rule));
            }

            return o;
        }
        fromJSON(json) {
            this.type = 'json';
            if (typeof json.b == 'string')
                json.b = parseInt(json.b, 16);

            this.height = json.h;
            this.version = json.v;
            this.prev = json.p;
            this.merkle = json.m;
            this.time = json.t;
            this.bits = json.b;
            this.nonce = json.n;

            for (let i in json.tx) {
                let t = app.TX.fromJSON(json.tx[i])
                this.tx.push(t);
            }

            this.init();
            return this;
        }
        isValid(context) {
            this.emit("beforevalidation", context);
            let validator = new app.BLOCK.VALIDATOR(this, context);
            let res = validator.isValid();
            if (!res)
                this.validation_errors = validator.getErrors();
            this.emit("aftervalidation", res, validator.getLog(), validator.getErrors());
            return res;
        }
        getLastErrorCodes() {
            return this.validation_errors;
        }
        send() {
            throw new Error('TX::send must be implemented');
        }
        getId() {
            return this.hash;
        }
        getVersion() {
            return this.version;
        };
        getBits() {
            return this.bits;
        }
        getPrevId() {
            return this.prev;
        }
        getTime() {
            return this.time;
        }
        getNonce() {
            return this.nonce;
        }
    }

    block.fromJSON = (data) => {
        if (data instanceof app.BLOCK)
            return data;

        return (new app.BLOCK()).fromJSON(data);
    }

    block.fromHEX = (hex) => {
        return (new app.BLOCK()).fromHex(hex);
    }

    block.validate = (block, context) => {
        return block.isValid(context);
    }

    block.generateNewBlockTemplate = (timestamp, coinbaseBytes, keystore, currentValidatorsMerkle) => {
        let mempool = new app.BLOCK().getMemPool();
        let fee = 0;
        let txlist = [];
        for (let i in mempool) {
            fee += mempool[i].fee;
            txlist.push(mempool[i]);
        }

        let latest = new app.BLOCK().getTop();
        if (app.config.genesisMode)
            latest = { height: -1, id: '0000000000000000000000000000000000000000000000000000000000000000' };

        let coinbase = app.TX.createCoinbase(fee, coinbaseBytes, keystore.private, currentValidatorsMerkle, latest.height);
        txlist.unshift(coinbase.toJSON());

        return {
            v: app.config.blockversion,
            p: latest.id,
            h: latest.height + 1,
            t: timestamp,
            n: 0,
            b: 0,
            tx: txlist
        };

    }

    block.createNewBlock = (coinbaseBytes, keystore, currentValidatorsMerkle) => {
        if (!keystore)
            throw new Error('can not create new block without keystore');

        if (!currentValidatorsMerkle)
            throw new Error('can not create new block without current validators merkle');

        return new app.BLOCK().fromJSON(block.generateNewBlockTemplate(new app.BLOCK().getCurrentTime(), coinbaseBytes, keystore, currentValidatorsMerkle));
    }

    class validator {
        constructor(block, context) {
            this.block = block;
            this.context = context;
            this.errors = [];
            this.log = [];
        }
        addError(msg, code) {
            this.errors.push({ message: msg, code: code });
            return false;
        }
        getErrors() {
            return this.errors;
        }
        getLog() {
            return this.log;
        }
        isValid() {
            let res = 0, err = [];
            for (let i in validator.rules) {
                try {
                    let r = validator.rules[i].apply(this.block, [this, this.context || {}]);
                    this.log.push({ 'action': i, 'status': r });
                    if (r)
                        res += 1;
                } catch (e) {
                    this.errors.push({ code: e.code, message: e.message, exception: true });
                }
            }

            if (app.config.validationalert) {
                for (let k in this.errors) {
                    this.block.throwError(this.errors[k].message, this.errors[k].code);
                }
            }

            return res == Object.keys(validator.rules).length;
        }
        static addRule(name, fnc) {
            validator.rules[name] = fnc;
        }
    }
    validator.rules = {};

    block.VALIDATOR = validator;

    return block
}