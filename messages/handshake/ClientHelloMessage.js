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

/* ClientHello message layout:
 *      00: Version_Major (MSB)
 *      01: Version_Minor (LSB)
 *      02: UTC + random offset (MSB)
 *      03: UTC + random offset (continued)
 *      04: UTC + random offset (continued)
 *      05: UTC + random offset (LSB)
 * 06...33: Random (28 bytes)
 *      34: Session ID Length
 * .......: Session ID (if a session ID is present)
 *      ##: Cookie Length
 * .......: Cookie (if a cookie ID is present)
 *      ##: Cipher Suites Length (MSB)
 *      ##: Cipher Suites Length (LSB)
 * .......: Cipher Suites List (2 bytes per cipher suite)
 *      ##: Compression Methods Length
 * .......: Compression Methods List (1 byte per compression method) 
 */

// enums
let enums = require('../../enums.js');

// constants
// NOTE: we consider "UTC + random" to be one "random" code; the DtlsSession class is responsible for populating the first four bytes with a Utc value (with a random offset)
const RANDOM_LENGTH = 32; 
//
const MAX_SESSION_ID_LENGTH = (1 << 8) - 1;

function ClientHelloMessage() {
    this.dtlsVersion = null;
    this.random = null;
    this.sessionId = null;
    this.cookie = null;
    this.cipherSuites = null;
    this.compressionMethods = null;
}

exports.create = function(dtlsVersion, random, sessionId, cookie, cipherSuites, compressionMethods) {
    // validate inputs
    //
    // version
    if (!enums.isDtlsVersionValid(dtlsVersion)) {
        throw new RangeError();
    }
    // random
    if (Object.prototype.toString.call(random) != "[object Uint8Array]") {
        throw new TypeError();
    } else if (random.length != RANDOM_LENGTH) {
        throw new RangeError();
    }
    // sessionId
    if (typeof sessionId === "undefined") {
        throw new TypeError();
    } else if (sessionId === null) {
        // null sessionId (i.e. no sessionId) is acceptable
    } else if (!Array.isArray(sessionId)) {
        throw new TypeError();
    } else if (sessionId.length > MAX_SESSION_ID_LENGTH) {
        throw new RangeError();
    }
    // cookie
    if (typeof cookie === "undefined") {
        throw new TypeError();
    } else if (cookie === null) {
        // null cookie (i.e. no cookie) is acceptable
    //} else if (!Array.isArray(cookie)) {
    } else if (Object.prototype.toString.call(cookie) != "[object Uint8Array]") {
        throw new TypeError();
    } else if (cookie.length > enums.getMaximumCookieLength(version)) {
        throw new RangeError();
    }
    // cipherSuites
    // NOTE: null cipherSuites (i.e. no cipherSuites) seem nonsensical, but we could find no specs that say null is disallowed so we accept it
    if (!Array.isArray(cipherSuites)) {
        throw new TypeError();
    }
    // compressionMethods
    if (!Array.isArray(compressionMethods)) {
        throw new TypeError();
    } else if (compressionMethods.length == 0) {
        // NOTE: all ClientHello messages should contain at least one compression method (namely "NULL")
        throw new RangeError();
    }

    // create and initialize the new ClientHelloMessage object
    let result = new ClientHelloMessage();
    result.dtlsVersion = dtlsVersion;
    result.random = random; // including a 4-byte utc prepended to the random sequence
    result.sessionId = sessionId;
    result.cookie = cookie;
    result.cipherSuites = cipherSuites;
    result.compressionMethods = compressionMethods;

    // return the new ClientHelloMessage object
    return result;
}

ClientHelloMessage.prototype.toBuffer = function() {
    // calculate the length of our buffer
    let bufferLength = 0;
    bufferLength += 2; // Version
    bufferLength += RANDOM_LENGTH; // Random
    bufferLength += 1; // Session ID Length
    // sessionId is optional and will be null if none exists
    if (this.sessionId != null) {
        bufferLength += this.sessionId.Length;
    }
    bufferLength += 1; // Cookie Length
    // cookie is optional and will be null if none exists
    if (this.cookie != null)
    {
        bufferLength += this.cookie.length;
    }
    bufferLength += 2; // Cipher Suites Length
    bufferLength += (2 * this.cipherSuites.length); // Cipher Suites (2 bytes per entry)
    bufferLength += 1; // Compression Methods Length
    bufferLength += (1 * this.compressionMethods.length); // Compression Methods (1 byte per entry)
    
    // create our buffer (which we will then populate)
    let result = Buffer.alloc(bufferLength);
    // use offset to track the current offset while writing to the buffer    
    let offset = 0;

    // populate message header
    //
    // version (octets 0-1)
    result.writeUInt16BE(this.dtlsVersion, offset);
    offset += 2;
    // random (including UTC + random offset)
    let randomAsBuffer = new Buffer(this.random);
    randomAsBuffer.copy(result, offset, 0, randomAsBuffer.length);
    offset += randomAsBuffer.length;
    // sessionId length and sessionId
    if (this.sessionId == null)
    {
        result[offset] = 0;
        offset += 1;
    }
    else
    {
        let sessionIdAsBuffer = new Buffer(this.sessionId);
        result[offset] = sessionIdAsBuffer.length;
        offset += 1;
        sessionIdAsBuffer.copy(result, offset, 0, sessionIdAsBuffer.length);
        offset += sessionIdAsBuffer.length;
    }
    // cookie length and cookie
    if (this.cookie == null)
    {
        result[offset] = 0;
        offset += 1;
    }
    else
    {
        let cookieAsBuffer = new Buffer(this.cookie);
        result[offset] = cookieAsBuffer.length;
        offset += 1;
        cookieAsBuffer.copy(result, offset, 0, cookieAsBuffer.length);
        offset += cookieAsBuffer.length;
    }
    // cipher suites length (2 bytes per cipher suite)
    result.writeUInt16BE(this.cipherSuites.length * 2, offset);
    offset += 2;
    // cipher suites
    for (let iCipherSuite = 0; iCipherSuite < this.cipherSuites.length; iCipherSuite++)
    {
        result.writeUInt16BE(this.cipherSuites[iCipherSuite], offset);
        offset += 2;
    }
    // compression methods length
    result[offset] = this.compressionMethods.length;
    offset += 1;
    // compression methods
    for (let iCompressionMethod = 0; iCompressionMethod < this.compressionMethods.length; iCompressionMethod++)
    {
        result[offset] = this.compressionMethods[iCompressionMethod];
        offset += 1;
    }

    // return the buffer (result)
    return result;
}
