include "./merkleproof.circom";
include "./circomlib/circuits/comparators.circom";
include "./circomlib/circuits/poseidon.circom";
include "./circomlib/circuits/eddsaposeidon.circom";
include "./circomlib/circuits/gates.circom";
include "./circomlib/circuits/bitify.circom";

// include for revocation bit
include "./util.circom";

template AttributePresentation(depth, revocDepth) {
		/*
		* Private Inputs
		*/
		// Meta
		signal input pathMeta[depth];
		signal input lemmaMeta[depth + 2];
		signal input meta[8]; //Fixed Size of meta attributes in each credential
		signal input signatureMeta[3];
		signal input pathRevocation[revocDepth];
		signal input lemmaRevocation[revocDepth + 2];
		signal input revocationLeaf;
		signal input signChallenge[3];
		signal input issuerPK[2];
		// Content
		signal input lemma[depth + 2];
		/*
		* Public Inputs
		*/
		// Meta
		signal input challenge; //6
		signal input expiration; //7
		signal output type; // 0
		signal output revocationRoot; //1
		signal output revoked; //2
		signal output challengeIssuerHash; //3
		signal output deligatable; //4
		// Content
		signal input path[depth]; //8
		signal output attributeHash; //5
		/*
		* Meta calculations
		*/
		type <== meta[1];
		revocationRoot <== lemmaRevocation[revocDepth + 1];
		deligatable <== meta[6];

		component hashMeta[6]; 
		for(var i=0;i<6;i++) {
				hashMeta[i] = Poseidon(1);
		}

		component hashMetaLR[4];
		for(var i=0; i<4; i++) {
				hashMetaLR[i] = HashLeftRight();
		}

		// Check merkle proof
		component merkleProofMeta = MerkleProof(depth);

		merkleProofMeta.lemma[0] <== lemmaMeta[0];
		merkleProofMeta.lemma[depth + 1] <== lemmaMeta[depth + 1];

		for (var i=0;i<depth;i++) {
				merkleProofMeta.path[i] <== pathMeta[i];
				merkleProofMeta.lemma[i + 1] <== lemmaMeta[i + 1];
		}	
		// Check merkle proof signatureMeta
		component eddsaVerify = EdDSAPoseidonVerifier();
		eddsaVerify.enabled <== 1;
		eddsaVerify.Ax <== issuerPK[0];
		eddsaVerify.Ay <== issuerPK[1];
		eddsaVerify.R8x <== signatureMeta[0];
		eddsaVerify.R8y <== signatureMeta[1];
		eddsaVerify.S <== signatureMeta[2];
		eddsaVerify.M <== lemmaMeta[depth + 1];
		// Check meta data by merkle proof	
		// Check id
		hashMeta[0].inputs[0] <== meta[0];
		lemmaMeta[0] === hashMeta[0].out;
		// Check type
		lemmaMeta[1] === meta[1];
		// Check holder key
		meta[2] ==> hashMeta[1].inputs[0];
		meta[3] ==> hashMeta[2].inputs[0];
		hashMetaLR[0].left <== hashMeta[1].out;
		hashMetaLR[0].right <== hashMeta[2].out;
		lemmaMeta[2] === hashMetaLR[0].hash;
		// Check registry and expiration / subtree A
		meta[5] ==> hashMeta[3].inputs[0];
		hashMetaLR[1].left <== meta[4];
		hashMetaLR[1].right <== hashMeta[3].out;
		// Check deligatable and empty object / subtree B
		meta[6] ==> hashMeta[4].inputs[0];
		hashMetaLR[2].left <== hashMeta[4].out;
		// Hash of empty string
		hashMetaLR[2].right <== 19014214495641488759237505126948346942972912379615652741039992445865937985820;
		// Build subtree AB
		hashMetaLR[3].left <== hashMetaLR[1].hash;
		hashMetaLR[3].right <== hashMetaLR[2].hash;
		lemmaMeta[3] === hashMetaLR[3].hash;
		// Check expiration
		component le = LessEqThan(64);
		le.in[0] <== expiration;
		le.in[1] <== meta[5];
		1 === le.out;
		// Check revocation
		// Check leaf index
		signal leafIndex1;
		leafIndex1 <-- meta[0] \ 252;
		var leafIndex2 = 0;
		for (var i=0; i<revocDepth; i++) {
			leafIndex2 += pathRevocation[i] * (2 ** i);
		}
		leafIndex1 === leafIndex2;
		// Check revocation list with merkle proof
		revocationLeaf ==> hashMeta[5].inputs[0];
		hashMeta[5].out === lemmaRevocation[0];
		component merkleProofRevocation = MerkleProof(revocDepth);
		merkleProofRevocation.lemma[0] <== lemmaRevocation[0];
		merkleProofRevocation.lemma[revocDepth + 1] <== lemmaRevocation[revocDepth + 1];
		for (var i=0; i<revocDepth; i++) {
				merkleProofRevocation.path[i] <== pathRevocation[i];
				merkleProofRevocation.lemma[i + 1] <== lemmaRevocation[i + 1];
		}	
		// Check revocation in revocationLeaf
		var div = meta[0] \ 252; // merkle tree leaf number -> e.g. id 1234500 / 252 = 4898-th leave 
		var position = meta[0] - (252 * div); // leave's bit position k e.g. id 1234500 - (252*4989) = 204-th
		meta[0] === div * 252 + position; 
		assert(0 <= position <= 251); // Ensure values are not negatives nor excessively larger
		/*
		component greaterThan = GreaterThan(252);
		greaterThan.in[0] <== position;
		greaterThan.in[1] <== 0;
		greaterThan.out === 1 ; // Is position greater than 0?

		component lessThan = LessThan(252);
		lessThan.in[0] <== position;
		lessThan.in[1] <== 252;
		lessThan.out === 1 ; // Is position smaller than 252?
		*/
		// Get k-th bit position value from a leave
		signal output revocationBit;
		component extractKthBit = extractKthBit(253);
		//inputs
		extractKthBit.in <== revocationLeaf;
    	extractKthBit.k <== position;
		// bit value output
		revocationBit <== extractKthBit.outBit;

		// Hash challenge issuers ppk
		component hashMeta3 = Poseidon(3);
		challenge ==> hashMeta3.inputs[0];	
		issuerPK[0] ==> hashMeta3.inputs[1];	
		issuerPK[1] ==> hashMeta3.inputs[2];	
		challengeIssuerHash <== hashMeta3.out;
		// Check challenge signature
		component eddsaVerifyChallenge = EdDSAPoseidonVerifier();
		eddsaVerifyChallenge.enabled <== 1;
		eddsaVerifyChallenge.Ax <== meta[2];
		eddsaVerifyChallenge.Ay <== meta[3];
		eddsaVerifyChallenge.R8x <== signChallenge[0];
		eddsaVerifyChallenge.R8y <== signChallenge[1];
		eddsaVerifyChallenge.S <== signChallenge[2];
		eddsaVerifyChallenge.M <== challenge;

		/*
		* Content calculations
		*/
		attributeHash <== lemma[0];
		// check merkle root with merkle root of meta which is already checked
		lemma[depth + 1] === lemmaMeta[depth + 1];
		component merkleProof = MerkleProof(depth);

		merkleProof.lemma[0] <== lemma[0];
		merkleProof.lemma[depth + 1] <== lemma[depth + 1];

		for (var i=0;i<depth;i++) {
				merkleProof.path[i] <== path[i];
				merkleProof.lemma[i + 1] <== lemma[i + 1];
		}	
}

component main = AttributePresentation(4, 13);
