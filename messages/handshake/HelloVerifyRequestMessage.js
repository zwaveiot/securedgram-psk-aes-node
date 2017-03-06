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

/* HelloVerifyRequest message layout:
 *      00: Version_Major (MSB)
 *      01: Version_Minor (LSB)
 *      02: Cookie length
 * .......: Cookie (if a cookie ID is present)
 */

let enums = require('../../enums.js');

// constants
const MIN_LENGTH = 3;

function HelloVerifyRequestMessage() {
    this.dtlsVersion = null;
    this.cookie = null;
}

exports.create = function(dtlsVersion, cookie) {
    // validate inputs
    //
    // dtlsVersion
    if (!enums.isVersionValid(dtlsVersion)) {
        throw new RangeError();
    }
    // cookie
    if (typeof cookie === "undefined") {
        throw new TypeError();
    } else if (cookie === null) {
        // null cookie (i.e. no cookie) is NOT acceptable
        throw new TypeError();
    } else if (!Array.isArray(cookie)) {
        throw new TypeError();
    } else if (cookie.length > enums.getMaximumCookieLength(dtlsVersion)) {
        throw new RangeError();
    }

    // create and initialize the new HelloVerifyRequestMessage object
    let result = new HelloVerifyRequestMessage();
    result.dtlsVersion = dtlsVersion;
    result.cookie = cookie;

    // return the new HelloVerifyRequestMessage object
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
    
    // create the new HelloVerifyRequestMessage object
    let result = new HelloVerifyRequestMessage();

    // parse buffer
    //
    // dtlsVersion (octets 0-1)
    result.dtlsVersion = buffer.readUInt16LE(currentOffset);
    currentOffset += 2;
    // cookie length (octet 2)
    let cookieLength = buffer[currentOffset];
    currentOffset += 1;
    // verify that the buffer length is long enough to fit the cookie
    if (buffer.length - currentOffset < cookieLength) {
        // if the buffer is not big enough, return null
        return null;
    }
    // cookie
    result.cookie = Buffer.alloc(cookieLength);
    buffer.copy(result.cookie, 0, currentOffset, currentOffset + cookieLength);
    currentOffset += cookieLength;

    // return the new HelloVerifyRequestMessage object
    return {message: result, bytesConsumed: currentOffset - initialOffset};
}
