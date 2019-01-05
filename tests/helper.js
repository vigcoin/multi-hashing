const fs = require('fs');
const assert = require('assert');
const path = require('path');

const fixturesFolder = path.resolve(__dirname, './fixtures');

function test(filename, hash) {
    fs.readFileSync(path.join(fixturesFolder, filename))
        .toString()
        .split('\n')
        .map((line) => {
            if (line) {
                const [expected, data] = line.split(/\s+/);
                try {
                    var b = new Buffer(data, 'hex');
                    assert.deepStrictEqual(hash(b).toString('hex'), expected);

                } catch (e) {
                    console.log(e);
                    assert(data === 'x');
                }
            }
        });
}

module.exports = {
    test
}