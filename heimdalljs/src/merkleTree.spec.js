const expect = require('chai').expect;
const assert = require('chai').assert;
const fs = require('fs').promises;
const path = require('path');

const {MerkleTree} = require('./crypto/merkleTree');
const {merklePoseidon} = require('./crypto/poseidon.js');
const {signPoseidon} = require("../circomlib/eddsa.js");
const {getSecretKey, getRevocationTree} = require("../cli/util");

//Verifiable credential components
const {AttributePresentation} = require("./presentation/attribute");
const credential = require('../test/attribute/cred_holder.json');
const secret_key_holder_path = './test/attribute/holder_sk.txt';
const public_key_issuer = require('../test/attribute/issuer_pk.json');
const { exit } = require('process');

const generateZeroArray = (numberOfLeaves, mapOfPositions = []) => {
    const zeroArray = new Array(numberOfLeaves).fill(0);
    mapOfPositions.forEach((position, value) => {
        zeroArray[position] = value;
    });
    return zeroArray;
};

const testMerkleProofBit = (MerkleTree, position) => {
    // Given a Merkle Tree, generate a proof for a given index
    // Lemma lenght is depth + 2
    const proof = MerkleTree.generateProof(position);

    // Test output sizes
    // lemma = index_value, neighbour, intermediary_nodes, root
    expect(proof.lemma.length).to.equal(MerkleTree.depth + 2);
    expect(proof.path.length).to.equal(MerkleTree.depth);
    // test proof validation - validate()
    expect(proof.validate()).to.equal(true);
    //Tamper the proof 
    const tamper = proof.lemma[proof.lemma.length - 1];
    proof.lemma[0] = tamper;
    expect(proof.validate()).to.equal(false);
};

const testMerkleProofOnCredential = async (credential, position, cred_type) => {
    if(cred_type == 'attribute'){
        try {
            //console.debug(credential);
            let undefined; // force an 'undefined' variable
            // the code forces a credential to have a revocation tree
            // get the revocation tree from the credential
            let revocationTree = await getRevocationTree(treeName = undefined, source = credential.attributes[4]);
            //read holder secret key 
            let secretKey = await getSecretKey(secret_key_holder_path);
            let presentation = new AttributePresentation(
                credential          = credential,
                expiration          = credential.attributes[5],
                revocation          = revocationTree,
                challenge           = 1234,
                sk                  = secretKey,
                issuerPk            = public_key_issuer,
                signatureGenerator  = signPoseidon,
                treeGenerator       = merklePoseidon,
                index               = Number(position)
            );
            //console.debug(presentation);
            // generate merkle proof
            let proof = await presentation.generate();
            expect(proof).to.equal(true); // implicitly runs verifyProof too
            //console.debug(presentation.output);
            // check output value was confined into the credential
            expect(credential.attributes).that.does.include(presentation.output['content']['attribute']);
            return Promise.resolve(true); 
        } catch (error) {
            return Promise.reject(false);
        }
        
    }else{
        // console.log("Credential type: " + cred_type + " not supported\n" );
        return Promise.reject(false);
    }
};

describe('MerkleTree class', () => {
    let merkleTree;
    before(async () => {
        const input = [1,1,2,2,3,3,4,4];
        merkleTree = new merklePoseidon(input);
    });

    after(async () => {
        // console.debug('Debug -> after: cleaning after testing');
        //process.exit(0);
    });

    describe('Tree generation', () => {
        const zeroArray = generateZeroArray(8);
        const merkleTree = merklePoseidon(zeroArray);
        it('All zeros', () => {    
            expect(merkleTree.leaves).to.have.deep.members(zeroArray);
        });
        it('Number of leaves', () => {
            expect(merkleTree.leaves.length).to.equal(zeroArray.length);
        });
    });

    describe('Merkle Tree edge-cases', () => {
        it('generateProof(0)', async () => {
            testMerkleProofBit(merkleTree, 0);
        });
        /*
        it('generateProof(1)', async () => {
            testMerkleProofBit(merkleTree, 1);
        });
        it('generateProof(4)', async () => {
            testMerkleProofBit(merkleTree, 4);
        });
        it('generateProof(6)', async () => {
            testMerkleProofBit(merkleTree, 6);
        });
        it('generateProof(7)', async () => {
            testMerkleProofBit(merkleTree, merkleTree.leaves.length-1);
        });
        /*
        it('generateProof() - out of bound index', async () => {
            // MerkleTree.generateProof(position) throws a custom error
            testMerkleProofBit(merkleTree, merkleTree.leaves.length+1);
        });
        */
        it('generateProof_from_credential()', async () => {
            let res = await testMerkleProofOnCredential(credential, 8, 'attribute');
     
            // attribute[8] = 'John'
            //console.log(res);
            expect(res).to.be.equal(true);
            //console.log("hrllo end\n");
        });

    });

});