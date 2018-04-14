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
                assert.deepStrictEqual(hash(new Buffer(data, 'hex')).toString('hex'), expected);
            }
        });
}

module.exports = {
    test
}