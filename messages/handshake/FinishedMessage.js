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

/* Finished message layout:
 *   00-11: verifyData (12 bytes)
 */

let enums = require('../../enums.js');
let SerializationHelper = require('../../helpers/SerializationHelper.js');

// constants
const VERIFY_DATA_LENGTH = 12;
//
const MIN_LENGTH = VERIFY_DATA_LENGTH;

function FinishedMessage() {
    this.verifyData = null;
}

/**
 * Returns a new FinishedMessage
 * @param {Buffer} verifyData - Verify data
 */
exports.create = function(verifyData) {
    // validate inputs
    //
    // verifyData
    if (Buffer.isBuffer(verifyData) === false) {
        // verifyData must be a Buffer
        throw new TypeError();
    } else if (verifyData.length !== VERIFY_DATA_LENGTH) {
        throw new RangeError();
    }

    // create and initialize the new FinishedMessage object
    let result = new FinishedMessage();
    // verifyData (NOTE: copied from passed-in buffer; we do this so that changes to the original Buffer do not modify our copy and vice-versa)
    result.verifyData = Buffer.alloc(verifyData.length);
    verifyData.copy(result.verifyData);

    // return the new FinishedMessage object
    return result;
}

/**
 * Parses the Finished message contained in the input Buffer; returns a tuple containing the parsed message ('message') as a FinishedMessage and the bytes consumed ('bytesConsumed') as a whole number.
 * @param {Buffer} buffer - The input buffer containing the Finished message
 * @param {number} offset=0 - The byte-offset within the buffer at which to start parsing
 */
// NOTE: this function returns null if a complete message could not be parsed (and does not validate any data in the returned message); it can also throw an error if the supplied arguments are invalid
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
    
    // create the new FinishedMessage object
    let result = new FinishedMessage();

    // parse buffer
    //
    // verifyData
    result.verifyData = Buffer.alloc(VERIFY_DATA_LENGTH);
    buffer.copy(result.verifyData, 0, currentOffset, currentOffset + VERIFY_DATA_LENGTH);
    currentOffset += VERIFY_DATA_LENGTH;

    // return the new FinishedMessage object
    return {message: result, bytesConsumed: currentOffset - initialOffset};
}

/**
  * Returns a Buffer consisting of the FinishedMessage
  */
  FinishedMessage.prototype.toBuffer = function() {
    // validate the object instance's fields
    //
    // verifyData
    if (Buffer.isBuffer(this.verifyData) === false) {
        // verifyData must be a Buffer
        throw new TypeError();
    } else if (this.verifyData.length !== VERIFY_DATA_LENGTH) {
        throw new RangeError();
    }

    // calculate the length of our buffer
    let bufferLength = 0;
    bufferLength += VERIFY_DATA_LENGTH; // verifyData

    // create our buffer (which we will then populate)
    let result = Buffer.alloc(bufferLength);
    // use currentOffset to track the current offset while writing to the buffer    
    let currentOffset = 0;

    // populate the result buffer
    //
    // verifyData
    this.verifyData.copy(result, currentOffset, 0, VERIFY_DATA_LENGTH);
    currentOffset += VERIFY_DATA_LENGTH;

    // return the buffer (result)
    return result;
}
