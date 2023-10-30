const expect = require('chai').expect;
const fs = require('fs').promises;

const {RevocationRegistry} = require('./revocation');
const {merklePoseidon} = require('../src/crypto/poseidon.js');
const {signPoseidon} = require('../circomlib/eddsa');

const secretKeyPath = './test/attribute/ca_sk.txt';

const generateZeroArray = (numberOfLeaves, mapOfPositions = []) => {
    const zeroArray = new Array(numberOfLeaves).fill(0n);
    mapOfPositions.forEach((position, value) => {
        zeroArray[position] = value;
    });
    return zeroArray;
};

const testRevocationBit = (revocationRegistry, position) => {
    expect(revocationRegistry.getRevoked(position)).to.equal(false);
    revocationRegistry.update(position);
    expect(revocationRegistry.getRevoked(position)).to.equal(true);
    const positionTree = Math.floor(position / 252);
    console.debug('Debug -> it: positionTree >> ', positionTree);
    const positionLeaf = position - positionTree * 252;
    console.debug('Debug -> it: positionLeaf >> ', positionLeaf);
    const leaf = revocationRegistry.leaves[positionTree];
    console.debug('Debug -> it: leaf >> ', leaf);
    const elemBinReversed = Number(leaf).toString(2).split("").reverse().join("");
    console.debug('Debug -> it: elemBinReversed >> ', elemBinReversed);
    const bit = Number(elemBinReversed[positionLeaf]);
    console.debug('Debug -> it: bit >> ', bit);
    expect(bit).to.equal(1);
};

describe('RevocationRegistry class', () => {
    let secretKey;
    before(async () => {
        console.debug('Debug -> before: Loading the input files');
        secretKey = await fs.readFile(secretKeyPath, 'utf8');
        console.debug('Debug -> before: secretKey >> ', secretKey);

        //TODO: use in beforeEach later for the stateless tree
        revocationRegistry = new RevocationRegistry(secretKey, merklePoseidon, (sk, msg) => signPoseidon(sk, BigInt(msg)));
    });

    after(async () => {
        // console.debug('Debug -> after: cleaning after testing');
    });

    let revocationRegistry;
    // beforeEach(async () => {
    //     console.debug('Debug -> beforeEach: (re)instantiation RevocationRegistry');
    //     revocationRegistry = new RevocationRegistry(secretKey, merklePoseidon, (sk, msg) => signPoseidon(sk, BigInt(msg)));
    //     console.debug('Debug -> beforeEach: revocationRegistry >> ', revocationRegistry);
    // });

    const numberOfLeaves = 8192;
    describe('Tree generation', () => {
        // it('Depth', () => {//TODO: make a getter for depth, make the depth dynamic, test everything related to the tree generation in a separated test suite
        //     expect(revocationRegistry.depth).to.equal(13);
        // });
        it('Number of leaves', () => {
            expect(revocationRegistry.leaves.length).to.equal(numberOfLeaves);
        });
        it('All zeros', () => {
            const zeroArray = generateZeroArray(numberOfLeaves);
            expect(revocationRegistry.leaves).to.have.deep.members(zeroArray);
        });
    });

    describe('Revocation edge-cases', () => {
        it('getRevoked(0) update(0) getRevoked(0)', async () => {
            testRevocationBit(revocationRegistry, 0);
        });
        it('getRevoked(1) update(1) getRevoked(1)', async () => {
            testRevocationBit(revocationRegistry, 1);
        });
        it('getRevoked(161) update(161) getRevoked(161)', async () => {
            testRevocationBit(revocationRegistry, 161);
        });
        it('getRevoked(252) update(252) getRevoked(252)', async () => {
            testRevocationBit(revocationRegistry, 252);
        });
        it('getRevoked(253) update(253) getRevoked(253)', async () => {
            testRevocationBit(revocationRegistry, 253);
        });
        it('getRevoked(10000) update(10000) getRevoked(10000)', async () => {
            testRevocationBit(revocationRegistry, 10000);
        });
        it('getRevoked(10100) update(10100) getRevoked(10100)', async () => {
            testRevocationBit(revocationRegistry, 10100);
        });
        it('getRevoked(2064382) update(2064382) getRevoked(2064382)', async () => {
            testRevocationBit(revocationRegistry, 2064382);
        });
    });
});