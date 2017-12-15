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

'use strict';

 /* PskClientKeyExchange message layout:
 *   00-01: identityLength (2 bytes, BE)
 * .......: identity (0+ bytes)
 */

let enums = require('../../enums.js');
let SerializationHelper = require('../../helpers/SerializationHelper.js');

// constants
const MAX_IDENTITY_LENGTH = (1 << 16) - 1;
//
const MIN_LENGTH = 2;

function PskClientKeyExchangeMessage() {
    this.identity = null;
}

/**
 * Returns a new PskClientKeyExchangeMessage
 * @param {Buffer} identity - Identity
 */
exports.create = function(identity) {
    // validate inputs
    //
    // identity
    if (Buffer.isBuffer(identity) === false) {
        // identity must be a Buffer (zero-length is permissable, whereas null is not)
        // NOTE: per RFC 4279, identities must be provided (and indeed a "zero-length PSK" could not be distinguished from a "missing" identity by some PSK ciphersuites)
        throw new TypeError();
    } else if (identity.length > MAX_IDENTITY_LENGTH) {
        // identity length may not exceed the maximum length allowed by RFC 4279
        throw new RangeError();
    }

    // create and initialize the new PskClientKeyExchangeMessage object
    let result = new PskClientKeyExchangeMessage();
    // identity
    result.identity = Buffer.alloc(identity.length);
    identity.copy(result.identity);

    // return the new PskClientKeyExchangeMessage object
    return result;
}

/**
 * Parses the PskClientKeyExchange message contained in the input Buffer; returns a tuple containing the parsed message ('message') as a PskClientKeyExchangeMessage and the bytes consumed ('bytesConsumed') as a whole number.
 * @param {Buffer} buffer - The input buffer containing the PskClientKeyExchange message
 * @param {number} offset=0 - The byte-offset within the buffer at which to start parsing
 */
// NOTE: this function returns null if a complete message could not be parsed (and does not validate any data in the returned message)
// NOTE: offset is optional (default: 0)
exports.fromBuffer = function(buffer, offset) {
    /** BEGINNING OF STANDARD fromBuffer(...) HEADER - DO NOT MODIFY */
    //
    // validate input arguments (returns true on success; returns false if buffer is not long enough; throws an error if arguments are programatically invalid)
    if (SerializationHelper.ValidateDeserializationArguments(buffer, offset, MIN_LENGTH) === false) return null;
    //
    // set our initialOffset to the passed-in offset (or to 0 if the passed-in offset argument is undefined)
    let initialOffset;
    if (typeof offset === 'undefined') { 
        initialOffset = 0; // default offset value
    } else { 
        initialOffset = offset; 
    }
    // set our currentOffset equal to our initialOffset (so we start parsing at the specified start offset).
    let currentOffset = initialOffset;
    //
    /** END OF STANDARD fromBuffer(...) HEADER - DO NOT MODIFY */
            
    // create the new PskClientKeyExchangeMessage object
    let result = new PskClientKeyExchangeMessage();

    // parse buffer
    //
    // identityLength
    let identityLength = buffer.readUInt16BE(currentOffset);
    currentOffset += 2;
    // identity (if identityLength > 0)
    if (buffer.length - currentOffset < identityLength) {
        // if the buffer is not big enough, return null
        return null;        
    }
    result.identity = Buffer.alloc(identityLength);
    buffer.copy(result.identity, 0, currentOffset, currentOffset + identityLength);
    currentOffset += identityLength;

    // return the new PskClientKeyExchangeMessage object
    return {message: result, bytesConsumed: currentOffset - initialOffset};
}

/**
  * Returns a Buffer consisting of the PskClientKeyExchangeMessage
 */
PskClientKeyExchangeMessage.prototype.toBuffer = function() {
    // validate the object instance's fields
    //
    // identity
    if (Buffer.isBuffer(this.identity) === false) {
        // identity must be a Buffer (zero-length is permissable, whereas null is not)
        // NOTE: per RFC 4279, identities must be provided (and indeed a "zero-length PSK" could not be distinguished from a "missing" identity by some PSK ciphersuites)
        throw new TypeError();
    } else if (this.identity.length > MAX_IDENTITY_LENGTH) {
        // identity length may not exceed the maximum length allowed by RFC 4279
        throw new RangeError();
    }

    // calculate the length of our buffer
    let bufferLength = 0;
    bufferLength += 2; // identityLength
    bufferLength += this.identity.length;
    
    // create our buffer (which we will then populate)
    let result = Buffer.alloc(bufferLength);
    // use currentOffset to track the current offset while writing to the buffer    
    let currentOffset = 0;

    // populate the result buffer
    //
    // identityLength
    let identityLength = this.identity.length;
    result.writeUInt16BE(identityLength, currentOffset);
    currentOffset += 2;
    // identity
    this.identity.copy(result, currentOffset);
    currentOffset += identityLength;

    // return the buffer (result)
    return result;
}
