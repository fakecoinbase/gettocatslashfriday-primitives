### Serializable primitives

Serializable primitives for friday blockchain framework. This module define and helps redefine primitives:
- block
- tx

Can convert tx/block data into hex and json (and back). 

### App

App instance have next methods:
`definePrimitive(cls)` - redefine abstract primitive class
`defineTx(cls)` - redefine tx class
`defineBlock(cls)` - redefine block class, must be invoked after tx redefine

and getters:
`app.Transaction` - tx class
`app.Block` - block class

## Config

```javascript
{
    validationalert: true,
    genesisMode: false, // genesisMode help make first block
    blockversion: 1,//supperted block version
    txversion: 1//supported transaction verion
}
```
 
# validationalert
If true - throw exception on each validation error, false - only add errors to log.

# genesisMode
Used for create genesis block with empty prev and 0 height.

# versions
If transaction/block version is bigger then supported - tx/block fire event unsupportedversion with params `listenerCallback(supportedversion, blockOrTxversion) {...}` 

## Primitive

Primitive is abstract class, extends with EventEmitter. Some methods in primitive muse be redefined:
```javascript
throwError(message, code); //create exception
getAddressByPublicKey(publicKeyHex); //generate address from public key
getPublicKeyByPrivateKey(privateKeyHex);//get public key by private key
getBlockValue(fee, height);//return block value for current height, based on emission
isValidAddress(address);//check validity of address
addressToHexValue(address);//return hex value(pubkeyhash) from address string
hexValueToAddress(hex);//return address from pubkeyhash
createHash(binaryOrHex);//hashing method
sign(privateKeyBinary, hash);//sign data with EC
verify(pubkey, sign, hash2sign);//verify {sign} for message {hash2sign} with {pubkey} EC
getOut(hash, index);//get previous output (proof) for input {hash:index}
getMerkleRoot(list);//generate merkle root for list
getMemPool();//return mempool list (json tx list)
getTop();//return {height: 'int-current-height', 'id':'current-top-block-hash'}
getCurrentTime(); //get current timestamp, by default: parseInt(Date.now()/1000);
```

This methods must be redefined with your code, example in __tests/crypto.js

## Tx

# hex format

Hex buffers creates from json output with apply bitowl protocol https://www.npmjs.com/package/bitowl for more details you can read documentation here: https://github.com/gettocat/bitowl

# json format

```javascript
{
    v: 'int-supported-tx-version',
    s: //signature data
        [
            [
                'signdata of first input',
                'pubkey of first input'
            ],
            //...
        ],
    in: //input data
        [
            {
                hash:
                    'prevout hash',
                index: 'int-prevout index'
            }
            //...
        ],
    out://output tx info
        [
            {
                address: 'address-destination',
                amount: 'amount'
            },
            //...
        ]
}
```

coinbase tx:
```javascript
{
    v: 'int-supported-tx-version',
    s: //signature data
        [
            [
                'signdata of first input',
                'pubkey of first input'
            ],
            //...
        ],
    out://output tx info
        [
            {
                address: 'address-destination',
                amount: 'amount'
            },
            //...
        ],
    cb: '001133',//coinbase bytes or hex
    //next two params used for ddPoS from package, readmore: https://github.com/gettocat/consensusjs 
    m: 'merkle root of validator pubkeys list',
    k: 'pubkey of block-creator'    
}
```

# methods

```javascript
//setters: 
setVersion(ver)
setInputs(arr)
setOutputs(arr)

//for coinbase: 
setMerkle(merkle)
setPublicKey(key)
setCoinbase(coinbaseData)

//serialization: 
toJSON()
fromJSON(jsondata)
toHex()
toBuffer()
fromHex(hexOrBufferdata)

//additional:
setKeystore(keystore) // keystore is array of privatekeyhex, using for sign tx
setData(data) // additional data of tx (look https://github.com/gettocat/orwelldb) for more details

//getters:
getId()
getHash()
getFee()
getSize()
isCoinbase()
getInputs()
getOutputs()

isValid(context) // execute validator rules on current tx
getLastErrorCodes() // validation errors
signTransaction(private_keys) // sign tx with private_keys, if private_keys is not defined - try use keystore params 
verifyTransaction() // verify signs of tx (return true if ok, and throw exception if not okay)
```

# static methods:
```javascript
TX.createFromJSON(jsondata, private_keys) // create from json and sign with private_keys
TX.createFromRaw(inputs, outputs, keys, version, ds, coinbaseData) 
TX.createCoinbase(fee, coinbaseBytes, privateKey, merkle, height) // create coinbase tx
TX.fromJSON(jsondata)
TX.fromHEX(hexOrBuffer)
TX.validate(tx, context)
```

# additional
TX.VALIDATOR - validator class, have method:
`TX.VALIDATOR.addRule(rulename, callback)` - creates validation rule with name and callback `callback(validator_instance)`, in callback you can return true if data is valid, false - if invalid, and throw exception if need more information in logs. `getLastErrorCodes()` returns log information after validation. Also, events `beforevalidation` and `aftervalidation` exists. `aftervalidation` event returns: `listener_callback(result, loglist, errors_list)`


Method `send` must be reimplemented in child tx.

## Block

# hex format

Hex buffers creates from json output with apply bitowl protocol https://www.npmjs.com/package/bitowl for more details you can read documentation here: https://github.com/gettocat/bitowl

# json format

```javascript
{
    v: 'current-block-version-int',
    p: 'previous-block-hash',
    m: 'merkle-root-of-txhashes list',
    t: 'block timestamp',
    b: 'additional info',
    n: 'additional info 2',
    tx: [txjson1,txjson2,...] //array with tx
}
```

# methods
```javascript
//add tx to block:
addTxFromHEX(hex)
addTxFromJSON(json)
addTx(tx)
addTxList(HEXorJSONorTXObjectArr) // add tx from any types of serialization

//serialization:
toHex()
toBuffer()
fromHex(hex)
toJSON()
fromJSON(json)

//validation:
getLastErrorCodes()
isValid(context)

//getters:
getId()
getVersion()
getBits()
getPrevId()
getTime()
getNonce()
getHash()

//txinfo:
getFee()
getSize()

//header info:
getHeader()
getHeaderBytes()
getHeaderHex()
```

# static methods
```javascript
BLOCK.fromJSON(jsondata)
BLOCK.fromHEX(hexdata)
BLOCK.validate(block, context)
BLOCK.generateNewBlockTemplate(timestamp, coinbaseBytes, keystore, currentValidatorsMerkle)  // creates new block template (json) with coinbase. keystore format is {public:'hex', private: 'hex'}
BLOCK.createNewBlock = (coinbaseBytes, keystore, currentValidatorsMerkle) // creates new block with coinbase and mempool info
```

# additional
BLOCK.VALIDATOR - validator class, have method:
`BLOCK.VALIDATOR.addRule(rulename, callback)` - creates validation rule with name and callback `callback(validator_instance)`, in callback you can return true if data is valid, false - if invalid, and throw exception if need more information in logs. `getLastErrorCodes()` returns log information after validation. Also, events `beforevalidation` and `aftervalidation` exists. `aftervalidation` event returns: `listener_callback(result, loglist, errors_list)`


Method `send` must be reimplemented in child block.


## Example

Look ./example.js