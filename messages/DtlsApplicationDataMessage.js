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
 *     00+: Data
 */

let enums = require('../enums.js');

function DtlsApplicationDataMessage() {
    this.data = null;
}

exports.create = function(data) {
    // validate inputs
    //
    // data
    if (data === undefined || data === null) {
        throw new TypeError();
    }

    // create and initialize the new ApplicationDataMessage object
    let result = new DtlsApplicationDataMessage();
    result.data = data;

    // return the new ApplicationDataMessage record object
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
    // } else if (buffer.length - currentOffset < MIN_LENGTH) {
    //     // buffer is not long enough for a full record; return null.
    //     return null;
    }
    
    // create the new ApplicationDataMessage object
    let result = new DtlsApplicationDataMessage();

    // parse buffer
    //
    // data (octets 0+)
    let dataLength = buffer.length - currentOffset;
    result.data = Buffer.alloc(dataLength);
    buffer.copy(result.data, 0, 0, dataLength);
    currentOffset += dataLength;

    // return the new ApplicationDataMessage object
    return {record: result, bytesConsumed: currentOffset - initialOffset};
}

DtlsApplicationDataMessage.prototype.toBuffer = function() {
    // create our buffer (which we will then populate)
    let result = Buffer.alloc(this.data.length);
    // use offset to track the current offset while writing to the buffer    
    let offset = 0;

    // populate record header
    //
    // data (octets 0+)
    let dataLength = this.data.length;
    this.data.copy(result, 0, 0, dataLength);
    offset += dataLength;

    // return the buffer (result)
    return result;
}