class App {
    constructor(config) {
        this.config = config;

        this.PRIMITIVE = require('./primitives/primitive');
    }
    definePrimitive(cls) {
        this.PRIMITIVE = cls;
        this.TX = require('./primitives/tx')(this);
        this.BLOCK = require('./primitives/block')(this);
    }
    defineBlock(cls) {
        this.BLOCK = cls;
    }
    defineTx(cls) {
        this.TX = cls;
    }
    get Transaction() {
        return this.TX;
    }
    get Block() {
        return this.BLOCK;
    }
}

module.exports = App;