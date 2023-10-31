const {stringifyBigInts} = require("../util");
const {PresentationTypes, Presentation} = require("./presentation");

class AttributePresentation extends Presentation {
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
        let proof = tree.generateProof(index);
        this.privateInput.lemma = proof.lemma;
        this.privateInput.path = proof.path;
        this.output.content = {
            attribute: cred.attributes[index]
        };

    }

    async verify(hasher, cred, root) {
        console.debug = function() {};
        console.debug("root", root)
        console.debug("this.revocationRoot", this.revocationRoot)
        if (!this.revocationRoot)
            this.revocationRoot = root;
        try {
            console.debug("verify(hasher, cred, root)");
            console.debug("this", this)
            let copy = JSON.stringify(stringifyBigInts(this));
            console.debug("copy-1", copy);
            let res = await this.verifyProof();
            console.debug("await this.verifyProof()", res);

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
            console.debug("this.verifyMeta()", res);
            const hashedAttribute = hasher([this.output.content.attribute]).toString();
            console.debug("hashedAttribute", hashedAttribute);
            console.debug("this.publicSignals[6]", this.publicSignals[6]);
            res &&= hashedAttribute === this.publicSignals[6];

            // Pass credentials, look for attribute position (index) within the array
            console.debug("cred", cred);
            if (cred)
                this.output.content.position = cred.attributes.indexOf(this.output.content.attribute);

            console.debug("JSON.stringify(stringifyBigInts(this))", JSON.stringify(stringifyBigInts(this)))
            res &&= copy === JSON.stringify(stringifyBigInts(this));
            console.debug("JSON.stringify(stringifyBigInts(this) (copy-2)", JSON.stringify(stringifyBigInts(this)));

            return res;
        } catch (err) {
            return Promise.reject(err);
        }
    }
}

module.exports = {AttributePresentation};