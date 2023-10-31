const {stringifyBigInts} = require("../util");
const {PresentationTypes, Presentation} = require("./presentation");

class MultipleAttributePresentation extends Presentation {
    constructor(
        cred,
        expiration,
        revocationLeaves,
        challenge,
        sk,
        issuerPK,
        signatureGenerator,
        treeGenerator,
        index
    ) {
        super(
            cred,
            expiration,
            revocationLeaves,
            challenge,
            sk,
            issuerPK,
            signatureGenerator,
            treeGenerator);
        this.type = PresentationTypes.attribute;
        let tree = treeGenerator(cred.attributes);

        // Generate proofs for every attribute
        let proof = [];
        this.privateInput.lemma = [];
        this.privateInput.path = [];
        this.output.content = {
            attribute: []
        };
        for (let i = 0; i < index.length; i++) {
            proof[i] = tree.generateProof(index[i]);
            this.privateInput.lemma[i] = proof[i].lemma;
            this.privateInput.path[i] = proof[i].path;
            this.output.content.attribute.push(cred.attributes[index[i]]) // Push the attribute "index[i]" into output content
        } 
    }

    async verify(hasher, cred, root) {
        if (!this.revocationRoot)
            this.revocationRoot = root;
        try {
            let copy = JSON.stringify(stringifyBigInts(this));
            let res = await this.verifyProof();
            res &&= await this.verifyMeta(
                0,
                1,
                2,
                3,
                4,
                5,
                7,
                8,
                hasher
            );
            res &&= hasher([this.output.content.attribute]).toString() === this.publicSignals[6];
            this.output.content.position = 0;
            // Pass credentials, look for attribute position (index) within the array
            if (cred)
                this.output.content.position = cred.attributes.indexOf(this.output.content.attribute);
            /*
            for (let i = 0; i < 4; i++) {
                this.output.content.position += (2 ** i) * this.publicSignals[9 + i];
            }
            */
            res &&= copy === JSON.stringify(stringifyBigInts(this));
            return Promise.resolve(res);
        } catch (err) {
            return Promise.reject(err);
        }
    }

    async verifyMultAttrs(hasher, cred, root, nAttrs) {
        if (!this.revocationRoot)
            this.revocationRoot = root;
        try {
            let copy = JSON.stringify(stringifyBigInts(this));
            let res = await this.verifyMultProof(nAttrs);
            console.log("Verify mult proof: ", res);
            res &&= await this.verifyMultMeta(
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                hasher
            );
            console.log("Verify meta: ", res);
            // Verify all necessary attribute hashes
            const fixed_index_length = 8;
            const data_array_length = fixed_index_length + nAttrs; // nAttrs = number of attributes to disclose
            this.output.content.position = [];
            
            let index = fixed_index_length;
            this.output.content.attribute.forEach(attr => {
                res &&= hasher([attr]).toString() === this.publicSignals[index];
                // Pass credentials, look for attribute position (index) within the array
                if (cred){
                    this.output.content.position[index%fixed_index_length] = cred.attributes.indexOf(attr);
                }
                index++;
            });
            /*
            for (let i = 0; i < 4; i++) {
                this.output.content.position += (2 ** i) * this.publicSignals[9 + i];
            }
            */
            res &&= copy === JSON.stringify(stringifyBigInts(this));
            return Promise.resolve(res);
        } catch (err) {
            return Promise.reject(err);
        }
    }
}

module.exports = {MultipleAttributePresentation};