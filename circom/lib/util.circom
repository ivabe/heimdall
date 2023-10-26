include "./circomlib/circuits/comparators.circom";
include "./circomlib/circuits/bitify.circom";

template ExtractKthBit(n) {
    signal input in;
    signal input k;
    signal output outBit; // bit value, must be either 0/1
   
    signal runningOutputBitSum[n+1];  // used to iteratively compute ∑_0_to_n binaryRepresentation[i]*IsEqual(i,k), where IsEqual() gives 1 if True, 0 if False
    runningOutputBitSum[0] <== 0;
    component bit_array = Num2Bits(n);
    bit_array.in <== in;
    
    component equality_check[n]; // used for IsEqual() components in the loop
    for (var i = 0; i<n; i++) {
        // if i = k then assing k_ith
        equality_check[i] = IsEqual();
        equality_check[i].in[0] <== k;
        equality_check[i].in[1] <== i;
        // ∑_0_to_251 n[i]*IsEqual(i,k)
        runningOutputBitSum[i+1] <== runningOutputBitSum[i] + bit_array.out[i] * equality_check[i].out;
        if(bit_array.out[i] * equality_check[i].out){
          //  log("Revocation position within the leaf ", k);
        }
    }
    outBit <== runningOutputBitSum[n];
}