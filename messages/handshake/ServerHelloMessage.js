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

/* ServerHello message layout:
 *      00: Version_Major (MSB)
 *      01: Version_Minor (LSB)
 *      02: UTC + random offset (MSB)
 *      03: UTC + random offset (continued)
 *      04: UTC + random offset (continued)
 *      05: UTC + random offset (LSB)
 * 06...33: Random (28 bytes)
 *      34: Session ID Length
 * .......: Session ID (if a session ID is present)
 * .......: Cipher Suite (2 bytes)
 * .......: Compression Method (1 byte) 
 */

let enums = require('../../enums.js');

// constants
const RANDOM_LENGTH = 32; // NOTE: the first four bytes are the Utc value (with a  random offset which should be set by the server)
const MIN_LENGTH = 40;
//
const MAX_SESSION_ID_LENGTH = (1 << 8) - 1;

function ServerHelloMessage() {
    this.dtlsVersion = null;
    this.random = null;
    this.sessionId = null;
    this.cipherSuite = null;
    this.compressionMethod = null;
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
    
    // create the new ServerHelloMessage object
    let result = new ServerHelloMessage();

    // parse buffer
    //
    // dtlsVersion (octets 0-1)
    result.dtlsVersion = buffer.readUInt16BE(currentOffset);
    currentOffset += 2;
    // random (octets 2-33)
    result.random = new Buffer.alloc(RANDOM_LENGTH);
    buffer.copy(result.random, 0, currentOffset, currentOffset + result.random.length);
    currentOffset += RANDOM_LENGTH;
    // sessionId length (octet 34)
    let sessionIdLength = buffer[currentOffset];
    currentOffset += 1;
    // verify that the buffer length is long enough to fit the session
    if (buffer.length - offset - MIN_LENGTH < sessionIdLength) {
        // if the buffer is not big enough, return null
        return null;
    }
    // sessionId
    result.sessionId = Buffer.alloc(sessionIdLength);
    buffer.copy(result.sessionId, 0, currentOffset, currentOffset + sessionIdLength);
    currentOffset += sessionIdLength;
    // cipherSuite (two octets)
    result.cipherSuite = buffer.readUInt16BE(currentOffset);
    currentOffset += 2;
    // compressionMethod (one octet)
    result.compressionMethod = buffer[currentOffset];
    currentOffset += 1;

    // return the new ServerHelloMessage object
    return {message: result, bytesConsumed: currentOffset - initialOffset};
}