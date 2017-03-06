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
 *   00-12: VerifyData
 */

let enums = require('../../enums.js');

// constants
const VERIFY_DATA_LENGTH = 12;
const MIN_LENGTH = 12;

function FinishedMessage() {
    this.verifyData = null;
}

exports.create = function(verifyData) {
    // validate inputs
    //
    // verifyData
    if (Object.prototype.toString.call(verifyData) != "[object Uint8Array]") {
        throw new TypeError();
    }
    if (verifyData.length != VERIFY_DATA_LENGTH) {
        throw new RangeError();
    }

    // create and initialize the new FinishedMessage object
    let result = new FinishedMessage();
    result.verifyData = verifyData;

    // return the new ClientHelloMessage object
    return result;
}

FinishedMessage.prototype.toBuffer = function() {
    // calculate the length of our buffer
    let bufferLength = 0;
    bufferLength += VERIFY_DATA_LENGTH; // Random

    // create our buffer (which we will then populate)
    let result = Buffer.alloc(bufferLength);
    // use offset to track the current offset while writing to the buffer    
    let offset = 0;

    // populate message header
    //
    // verifyData (octets 0-11)
    let verifyDataAsBuffer = new Buffer(this.verifyData);
    verifyDataAsBuffer.copy(result, offset, 0, verifyDataAsBuffer.length);
    offset += verifyDataAsBuffer.length;

    // return the buffer (result)
    return result;
}


// NOTE: this function returns null if a complete message could not be parsed (and does not validate any data in the returned message)
// NOTE: offset is optional (default: 0)
exports.fromBuffer = function(buffer, offset) {
    // use currentOffset to track the current offset while reading from the buffer    
    let initialOffset;
    let currentOffset;

    // validate inputs
    //
    // offset
    if (typeof offset === "undefined") {
        initialOffset = 0;
    } else if (typeof offset !== "number") {
        // if the offset is provided, but is not a number, then return an error
        throw new TypeError();        
    } else if (offset >= buffer.length) {
        throw new RangeError();
    } else {
        initialOffset = offset;    
    }
    currentOffset = initialOffset;
    // buffer
    if (typeof buffer === "undefined") {
        throw new TypeError();
    } else if (buffer  === null) {
        // null buffer is NOT acceptable
    } else if (Object.prototype.toString.call(buffer) != "[object Uint8Array]") {
        throw new TypeError();
    } else if (buffer.length - currentOffset < MIN_LENGTH) {
        // buffer is not long enough for a full message; return null.
        return null;
    }
    
    // create the new FinishedMessage object
    let result = new FinishedMessage();

    // parse buffer
    //
    // verifyData (octets 0-11)
    result.verifyData = Buffer.alloc(VERIFY_DATA_LENGTH);
    buffer.copy(result.verifyData, 0, currentOffset, currentOffset + VERIFY_DATA_LENGTH);
    currentOffset += VERIFY_DATA_LENGTH;

    // return the new ServerHelloMessage object
    return {message: result, bytesConsumed: currentOffset - initialOffset};
}