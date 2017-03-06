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

/* Record layout:
 *      00: Type (fixed value of "1")
 */

let enums = require('../enums.js');

// constants
const MIN_LENGTH = 1;
const MAX_LENGTH = 1;

function DtlsChangeCipherSpecMessage() {
    this.type = null;
}

exports.create = function(type) {
    // validate inputs
    //
    // type
    if (!enums.isChangeCipherSpecTypeValid(type)) {
        throw new RangeError();
    }

    // create and initialize the new DtlsChangeCipherSpecMessage object
    let result = new DtlsChangeCipherSpecMessage();
    result.type = type;

    // return the new DtlsChangeCipherSpecMessage record object
    return result;
}

// NOTE: this function returns null if a complete record could not be parsed (and does not validate any data in the returned record)
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
        // buffer is not long enough for a full record; return null.
        return null;
    }
    
    // create the new DtlsChangeCipherSpecMessage object
    let result = new DtlsChangeCipherSpecMessage();

    // parse buffer
    //
    // type (octet 0)
    result.type = buffer[currentOffset];
    currentOffset += 1;

    // return the new DtlsChangeCipherSpecMessage object
    return {record: result, bytesConsumed: currentOffset - initialOffset};
}

DtlsChangeCipherSpecMessage.prototype.toBuffer = function() {
    // create our buffer (which we will then populate)
    let result = Buffer.alloc(MAX_LENGTH);
    // use offset to track the current offset while writing to the buffer    
    let offset = 0;

    // populate record header
    //
    // type (octet 0)
    result[offset] = this.type;
    offset += 1;

    // return the buffer (result)
    return result;
}