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

/* ServerHelloDone message layout:
 * [no content]
 */

let enums = require('../../enums.js');

// constants
const MIN_LENGTH = 0;

function ServerHelloDoneMessage() {
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
    
    // create the new ServerHelloDoneMessage object
    let result = new ServerHelloDoneMessage();

    // parse buffer
    //
    // [no content]

    // return the new ServerHelloDoneMessage object
    return {message: result, bytesConsumed: currentOffset - initialOffset};
}
