const bitowl = require('bitowl');

module.exports = (app) => {
    class TX extends app.PRIMITIVE {
        constructor(data) {
            super();
            this.type = 'build';
            this.signed = false;

            this.hash = '';
            this.version = app.config.txversion;
            this.inputs = [];
            this.outputs = [];
            this.data = '';
            this.signdata = [];

            this.fee = 0;
            this.size = 0;

            this.coinbase = 0;
            this.merkle = '';
            this.key = '';

            this.isValidTransaction = 1;
            this.keystore = [];

            this.validation_errors = [];

            if (data) {
                if (!(data instanceof Buffer || typeof data == 'string'))
                    throw new Error('TX:Constructor, data must be string (hex) or buffer instance');

                this.hex = new Buffer(data, 'hex');
                this.type = 'raw';
                this.init();
            }

        }
        init() {
            if (this.type == 'build') {
                //sign
                this.signTransaction();
                //create hex
            }

            if (this.type == 'raw') {
                //decode hex
                this.fromJSON(bitowl.data.unpack(this.hex))
            }

            if (this.type == 'json') {
                //create hex
                this.hex = this.toBuffer();
            }

            //calculate fee,size,hash
            this.signed = this.verifyTransaction();
            this.hash = this.getId();
            this.size = this.hex.length;
            this.fee = 0;

            if (!this.coinbase) {
                let outval = 0, inval = 0;
                for (let i in this.inputs) {
                    if (this.inputs[i].hash && this.inputs[i].index != -1) {//not a coinbase
                        let out = this.getOut(this.inputs[i].hash, this.inputs[i].index);
                        inval += out.amount;
                    }
                }

                for (let i in this.outputs) {
                    outval += this.outputs[i].amount;
                }

                this.fee = inval - outval;
            }

            if (this.version > app.config.txversion) {
                this.emit("unsupportedversion", app.config.txversion, this.version);
            }//else is okay

        }
        setInputs(arr) {
            //setup signdata BEFORE this method
            for (let i in arr) {
                if (!arr[i].hash && arr[i].index != -1)
                    throw new Error('field hash is not exist for input of new tx.in[' + i + ']');

                if (arr[i].s) {
                    this.signdata[i] = arr[i].s;//[p.der, p.publicKey]
                }

                if (!arr[i].prevAddress && this.signdata[i]) {
                    arr[i].prevAddress = this.getAddressByPublicKey(this.signdata[i][1]);
                }

                if (!arr[i].prevAddress && this.keystore[i]) {
                    arr[i].prevAddress = this.getAddressByPublicKey(this.keystore[i]);
                }

                if (!arr[i].prevAddress)
                    throw new Error('field prevAddress is not entered for input of new tx.in[' + i + ']');

                this.inputs[i] = arr[i]

            }

            return this;
        }
        setOutputs(arr) {

            for (let i in arr) {

                if (arr[i].address) {
                    if (!this.isValidAddress(arr[i].address))
                        throw new Error('invalid address field for tx.out[' + i + ']');
                }

                this.outputs[i] = arr[i];
            }

            return this;
        }
        setMerkle(merkle) {
            this.merkle = merkle;
        }
        setPublicKey(key) {
            this.key = key;
        }
        setCoinbase(coinbaseData) {
            this.coinbase = coinbaseData;
        }
        toJSON() {

            let in_ = [];
            for (let i in this.inputs) {
                in_[i] = this.inputs[i];
                if (in_[i].prevAddress)
                    delete in_[i].prevAddress;
            }

            let o = {
                v: this.version,
                s: this.signdata,
                in: in_,
                out: this.outputs
            }

            if (this.coinbase) {
                o.cb = this.coinbase;
                o.m = this.merkle;
                o.k = this.key;
                delete o.in;
            }

            return o;
        }
        fromJSON(jsondata) {
            this.type = 'json';
            this.setVersion(jsondata.v);
            this.signdata = jsondata.s;
            this.setInputs(jsondata.in);
            this.setOutputs(jsondata.out);

            if (jsondata.ds)
                this.setData(ds);

            if (jsondata.cb) {
                this.setCoinbase(jsondata.cb);
                this.setMerkle(jsondata.m);
                this.setPublicKey(jsondata.k);

                if (!jsondata.in)
                    this.setInputs([{ index: -1 }]);
            }

            this.init();
            return this;
        }
        fromHex(hexOrBuffer) {
            this.type = 'raw';
            this.hex = new Buffer(hexOrBuffer, 'hex');
            this.init();
            return this;
        }
        setKeystore(keys) {
            this.keystore = keys;
            return this;
        }
        setVersion(version) {
            this.version = version;
            return this;
        }
        setData(data) {
            //datascript
            let dsc = "";
            if (data instanceof Array && data.length > 0) {
                let scriptslist = [];
                for (let i in data) {
                    if (data[i] instanceof dscript)
                        scriptslist.push(data[i].toHEX());
                    else
                        scriptslist.push(data[i]);
                }
                dsc = dscript.writeArray(scriptslist);
            } else
                dsc = this.datascripts;

            this.data = dsc;
            return this;
        }
        toHex() {
            return this.hex.toString('hex');
        }
        toBuffer(action) {
            for (let i in this.inputs) {
                if (this.type != 'build' && action != 'verify')
                    if (!this.signdata[i])
                        throw new Error('Signature for input [' + i + '] doesnt exist');
            }

            let d = this.toJSON();
            if (action == 'verify')
                delete d.s;//sign is not part of txhash
            return bitowl.data.pack(d);
        }
        getId(forse) {
            if (!this.hash || forse) {
                this.hash = this.createHash(this.toBuffer('verify')).toString('hex');
            }

            return this.hash;
        }
        getHash(forse) {
            return this.getId(forse);
        }
        getFee() {
            //calculate fee
            return this.fee;
        }
        getSize() {
            //return size of tx
            return this.size;
        }
        isCoinbase() {
            return !!this.coinbase;
        }
        getOutputs() {
            return this.outputs
        }
        getInputs() {
            return this.inputs
        }
        send() {
            throw new Error('TX::send must be implemented');
        }
        isValid(context) {
            this.emit("beforevalidation", context);
            let validator = new app.TX.VALIDATOR(this, context);
            let res = validator.isValid();
            if (!res)
                this.validation_errors = validator.getErrors();
            this.emit("aftervalidation", res, validator.getLog(), validator.getErrors());
            return res;
        }
        getLastErrorCodes() {
            return this.validation_errors;
        }
        signTransaction(private_keys) {
            //sign current data 
            if (!private_keys)
                private_keys = this.keystore;

            if (!private_keys || (!private_keys instanceof Array) || private_keys.length < this.inputs.length)
                throw new Error('Invalid keystore length, must be >=' + this.inputs.length + ' keys');

            let siglist = [];
            let txb = this.toBuffer('verify'),
                hash = this.createHash(txb);

            for (let i in this.inputs) {
                siglist[i] = [
                    this.sign(private_keys[i], new Buffer(hash, 'hex')).toString('hex'),
                    this.getPublicKeyByPrivateKey(private_keys[i])
                ];
            }

            this.signdata = siglist;
            this.hex = this.toBuffer();
        }
        verifyTransaction() {
            let res = [];
            let signable = this.toBuffer('verify');
            let hash2sign = this.createHash(new Buffer(signable, 'hex'));

            for (let i in this.inputs) {
                let pubkey = this.signdata[i][1];
                let sign = this.signdata[i][0];
                res[i] = this.verify(pubkey, sign, new Buffer(hash2sign, 'hex'));
                //sometimes one of signs in big tx - can not be verified - so, its thrown error, TODO: check EC and find this bug (signs and messagehash is equal)
            }

            let result = true;
            for (let i in res) {
                if (!res[i])
                    result = false;
            }

            if (!result)
                throw new Error('can not verify signature of transaction');

            return result;
        }
    }

    TX.createFromJSON = function (data, keys) {
        let incnt = 1;
        if (!data.cb) {
            if (!data.in)
                throw new Error('invalid txdata format, must exist fields txdata.in[]');
            incnt = data.in.length
        } else {
            if (!data.k || !data.m || !data.cb)
                throw new Error('invalid coinbase tx data format, must exist fields txdata.k, txdata.m, txdata.cb');

            if (!data.in || data.in.length == 0)
                data.in = [{ index: -1 }];
        }

        if (!keys || keys.length < incnt)
            throw new Error("at least " + incnt + " keys must exist");

        if (!data.out)
            throw new Error('invalid txdata format, must exist fields txdata.out[]');

        if (!(data.out instanceof Array) || data.out.length < 1)
            throw new Error("at least one input must be in tx.out");

        return app.TX.createFromRaw(data.in, data.out, keys, data.v, data.ds, {
            merkle: data.m,
            key: data.k,
            coinbase: data.cb
        });
    }

    TX.createFromRaw = function (inputs, outputs, keys, version, ds, coinbaseData) {
        let tx = new app.TX();

        if (!version)
            version = 1;

        tx
            .setVersion(version)
            .setKeystore(keys)
            .setInputs(inputs)
            .setOutputs(outputs)

        if (ds)
            tx.setData(ds);

        if (coinbaseData) {
            tx.setPublicKey(coinbaseData.key);
            tx.setMerkle(coinbaseData.merkle);
            tx.setCoinbase(coinbaseData.coinbase);
        }

        tx.init();
        return tx;
    }

    TX.createCoinbase = function (fee, coinbaseBytes, privateKey, merkle, height) {
        if (!fee)
            fee = 0;

        let temp = new app.TX();
        return TX.createFromJSON({
            v: app.config.txversion,
            out: [
                { address: temp.getAddressByPublicKey(temp.getPublicKeyByPrivateKey(privateKey)), amount: temp.getBlockValue(fee, height + 1) }
            ],
            m: merkle,
            k: temp.getPublicKeyByPrivateKey(privateKey),
            cb: new Buffer(coinbaseBytes, 'hex').toString('hex')
        }, [privateKey]);
    }

    TX.fromJSON = function (data) {
        return new app.TX().fromJSON(data);
    }

    TX.fromHEX = function (hex) {
        return new app.TX(hex);
    }

    TX.validate = function (tx, context) {
        return tx.isValid(context);
    }

    class validator {
        constructor(tx, context) {
            this.tx = tx;
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
                    let r = validator.rules[i].apply(this.tx, [this, this.context || {}]);
                    this.log.push({ 'action': i, 'status': r });
                    if (r)
                        res += 1;
                } catch (e) {
                    this.errors.push({ code: e.code, message: e.message, exception: true });
                }
            }

            if (app.config.validationalert) {
                for (let k in this.errors) {
                    this.tx.throwError(this.errors[k].message, this.errors[k].code);
                }
            }

            return res == Object.keys(validator.rules).length;
        }
        static addRule(name, fnc) {
            validator.rules[name] = fnc;
        }
    }
    validator.rules = {};

    TX.VALIDATOR = validator;
    return TX
}