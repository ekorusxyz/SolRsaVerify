pragma solidity ^0.8.9;

/*
    Copyright 2016, Adrià Massanet

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Checked results with FIPS test vectors
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-2rsatestvectors.zip
    file SigVer15_186-3.rsp

 */

library SolRsaVerify {
    bytes19 constant sha256Prefix = 0x3031300d060960864801650304020105000420; //changing sha256Prefix to hardcoded to save on gas, no need to have this as memory
    function memcpy(uint _dest, uint _src, uint _len) pure internal {
        unchecked {
        // Copy word-length chunks while possible
        for ( ;_len >= 32; _len -= 32) {
            assembly {
                mstore(_dest, mload(_src))
            }
            _dest += 32;
            _src += 32;
        }

        // Copy remaining bytes
            uint mask = 256 ** (32 - _len) - 1;
            assembly {
                let srcpart := and(mload(_src), not(mask))
                let destpart := and(mload(_dest), mask)
                mstore(_dest, or(destpart, srcpart))
            }
        }
    }

    /** @dev Verifies a PKCSv1.5 SHA256 signature
      * @param _sha256 is the sha256 of the data
      * @param _s is the signature
      * @param _e is the exponent
      * @param _m is the modulus
      * @return 0 if success, >0 otherwise
    */
    function pkcs1Sha256Verify(
        bytes32 _sha256,
        bytes memory _s, bytes memory _e, bytes memory _m
    ) public view returns (uint) {
        unchecked{

        uint slen = _s.length;
        uint elen = _e.length;
        uint mlen = _m.length;

      	//require(_m.length >= sha256Prefix.length+_sha256.length+11);
        //require(_m.length >= 19+_sha256.length+11); //sha256Prefix.length no longer returns the right number, plus, hardcoding saves gas. same for all the other replacements lower down
        //require(mlen >= 30+_sha256.length); //reduced unnecessary adding to save gas, left where the numbers are derived from in comments for future reference
        require(mlen >= 62); //wait, _sha256 is forced to be a bytes32, no reason to check its length
        /// decipher

        uint inputLen = 0x60+slen+elen+mlen;
        bytes memory input = new bytes(inputLen);
        { //stack too deep if i don't scope
            uint sptr;
            uint eptr;
            uint mptr;
            uint inputPtr;
            assembly {
                sptr := add(_s,0x20)
                eptr := add(_e,0x20)
                mptr := add(_m,0x20)
                mstore(add(input,0x20),slen)
                mstore(add(input,0x40),elen)
                mstore(add(input,0x60),mlen)
                inputPtr := add(input,0x20)
            }
            memcpy(inputPtr+0x60,sptr,slen);
            memcpy(inputPtr+0x60+slen,eptr,elen);
            //memcpy(inputPtr+0x60+slen+elen,mptr,mlen);
            memcpy(inputPtr+inputLen-mlen,mptr,mlen);
        }
        bytes memory decipher = new bytes(mlen);
        assembly {
            pop(staticcall(sub(gas(), 2000), 5, add(input,0x20), inputLen, add(decipher,0x20), mlen))
        }
        uint i;

        /// 0x00 || 0x01 || PS || 0x00 || DigestInfo
        /// PS is padding filled with 0xff
        //  DigestInfo ::= SEQUENCE {
        //     digestAlgorithm AlgorithmIdentifier,
        //     digest OCTET STRING
        //  }

        //uint paddingLen = decipherlen - 3 - sha256Prefix.length - 32;
        //uint paddingLen = decipherlen - 3 - 19 - 32;
        //uint paddingLen = decipherlen - 54;
        uint paddingLen = mlen - 52; //oh, one more savings here, paddingLen can be shifted by 2 to save on some extra adding in for loops. again will leave originals in comments for easy reference, I found it hard to figure out where these numbers came from looking back at my code

        if (decipher[0] != 0 || uint8(decipher[1]) != 1) {
            return 1;
        }
        //for (i = 2;i<2+paddingLen;i++) {
        for (i = 2;i<paddingLen;++i) {
            if (decipher[i] != 0xff) {
                return 2;
            }
        }
        //if (decipher[2+paddingLen] != 0) {
        if (decipher[paddingLen] != 0) {
            return 3;
        }
        ++paddingLen; //ok this is a weird hack, but it saves gas: offsetting paddinglen before these for loops to save more repeated adding in for loops
        //for (i = 0;i<sha256Prefix.length;i++) {
        for (i = 0;i<19;++i) {
            //if (decipher[3+paddingLen+i]!=sha256Prefix[i]) {
            //if (decipher[1+paddingLen+i]!=sha256Prefix[i]) { //shift paddinglen by 2
            if (decipher[paddingLen+i]!=sha256Prefix[i]) { // ++paddinglen
                return 4;
            }
        }
        paddingLen+=19;
        //for (i = 0;i<_sha256.length;++i) {
        for (i = 0;i<32;++i) {
            //if (decipher[3+paddingLen+sha256Prefix.length+i]!=_sha256[i]) {
            //if (decipher[3+paddingLen+19+i]!=_sha256[i]) {
            //if (decipher[22+paddingLen+i]!=_sha256[i]) {
            //if (decipher[20+paddingLen+i]!=_sha256[i]) { //shift paddinglen by 2
            if (decipher[paddingLen+i]!=_sha256[i]) { // ++paddinglen and then +=19
                //yes, I am leaving all these commented. I'm modifying this later to do other stuff and I had a hard time tracing why the numbers were what they were set to, so it's helpful
                return 5;
            }
        }
        }
        return 0;
    }

    /** @dev Verifies a PKCSv1.5 SHA256 signature
      * @param _data to verify
      * @param _s is the signature
      * @param _e is the exponent
      * @param _m is the modulus
      * @return 0 if success, >0 otherwise
    */
    function pkcs1Sha256VerifyRaw(
        bytes memory _data,
        bytes memory _s, bytes memory _e, bytes memory _m
    ) public view returns (uint) {
        return pkcs1Sha256Verify(sha256(_data),_s,_e,_m);
    }

}
