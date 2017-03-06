/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict'

let crypto;

exports.verifyCrypto = function() {
    // if crypto is already loaded, return success
    if (exports.crypto) {
        return true;
    }

    try {
        exports.crypto = require('crypto');
        // we successfully loaded the crypto library (i.e. nodejs was built with crypto)
        return true;
    } catch (err) {
        // catastrophic failure: we could not load the crypto library.
        return false;
    }
}

// Psuedo-Random Function (PRF) is used to create our master key and also for secret expansion (for key generation)
/* PRF input parameters:
 *   secret: PRF secret
 *   label: an ASCII string which will be prefixed to the seed (so that we can create multiple PRF outputs using a single seed, using a different label input for each one)
 *   seed: PRF seed
 *   outputLength: number of bytes to return */
exports.PRF = function(secret, label, seed, outputLength) {
    if (!exports.verifyCrypto()) return null;

    // convert label to a buffer (if it is not already a buffer)
    label = new Buffer(label);
    // convert seed to a buffer (if it is not already a buffer)
    seed = new Buffer(seed);

    // concatenate the label and seed
    let combinedSeed = Buffer.concat([label, seed]);
    // split the secret into two halves; if the secret has an odd number of bytes then include the middle byte in each half
    let secretEachHalfLength = (secret.length / 2) + (secret.length % 2);
    let secretFirstHalf = secret.slice(0, secretEachHalfLength);
    let secretSecondHalf = secret.slice((secret.length / 2) - (secret.length % 2), secret.length);

    // calculate P_MD5 using the first half of the secret
    let md5Result = P_hash(secretFirstHalf, combinedSeed, outputLength, 'md5');
    // calculate P_SHA1 using the first half of the secret
    let sha1Result = P_hash(secretSecondHalf, combinedSeed, outputLength, 'sha1');
    // xor the MD5 and SHA1 results to generate our final result
    let result = xorBuffers(md5Result, sha1Result);

    // return our result
    return result;
}

// P_hash expands a secret and seed into an arbitrary quantity of output data
/* P_hash input parameters:
 *   secret: hash secret
 *   seed: hash seed
 *   outputLength: number of bytes to return 
 *   algorithm: hash algorithm {'HMAC','SHA1'} */
function P_hash(secret, seed, outputLength, algorithm) {
    let result = Buffer.alloc(0); // empty buffer
    let hmac;

    // for the initial iteration, set the (initial) data to our seed
    let data = seed;
    while (result.length < outputLength) {
        // calculate the hmac for our current 'data' value (our seed on the initiatial iteration...or an iterative hmac of that seed in later iterations)
        hmac = exports.crypto.createHmac(algorithm, secret).update(data).digest();
        // save this hmac result as the 'data' input for the next iteration
        let dataForNextIteration = hmac;
        // concatenate the hmac and our seed
        data = Buffer.concat([hmac, seed]);
        // calculate an hmac for the hmac-plus-seed (which we will store in our output)
        hmac = exports.crypto.createHmac(algorithm, secret).update(data).digest();
        // add the hmac to our result
        result = Buffer.concat([result, hmac]);
        // restore the saved first-interation-stage hmac as the 'data' input for our next iteration
        data = dataForNextIteration;
    }

    // if our HMAC's output block size resulted in a length which is slightly too big, discard the extra bytes.
    if (result.length > outputLength) {
        let truncatedBuffer = Buffer.alloc(outputLength);
        result.copy(truncatedBuffer, 0, 0, outputLength);
        result = truncatedBuffer;
    }

    // return the hash result (with the number of octects/bytes specified as 'outputLength' by the caller)
    return result;
}

function xorBuffers(buffer1, buffer2) {
    let result = Buffer.alloc(buffer1.length);
    for (let i = 0; i < result.length; i++) {
        result[i] = buffer1[i] ^ buffer2[i];
    }
    return result;
}

exports.createPremasterSecret_FromPresharedKey = function(psk) {
    let pskBuffer = new Buffer(psk);
    let pskBufferLength = pskBuffer.length;
    let premasterSecret = Buffer.alloc(4 + (pskBufferLength * 2));
    premasterSecret.writeUInt16BE(pskBufferLength, 0);
    premasterSecret.writeUInt16BE(pskBufferLength, 2 + pskBufferLength);
    pskBuffer.copy(premasterSecret, pskBufferLength + 4, 0, pskBufferLength);
    return premasterSecret;
}
