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
 *   00-01: serverVersion (2 bytes, BE)
 *      02: cookieLength (1 byte)
 * .......: cookie (0-32 bytes)
 */

let enums = require('../../enums.js');
let SerializationHelper = require('../../helpers/SerializationHelper.js');

// constants
const MIN_LENGTH = 3;

function HelloVerifyRequestMessage() {
    this.serverVersion = null;
    this.cookie = null;
}

/**
 * Returns a new HelloVerifyRequestMessage
 * @param {(DtlsVersion|Number)} serverVersion - Server DTLS version
 * @param {(Buffer|null)} cookie=null - Cookie (optional)
 */
exports.create = function(serverVersion, cookie) {
    // validate inputs
    //
    // serverVersion
    if (!enums.isDtlsVersionValid(serverVersion)) {
        throw new RangeError();
    }
    // cookie
    if (typeof cookie === "undefined") {
        // cookie is optional; this is allowed; set the local (passed-by-value) variable to null
        cookie = null;
    } else if (cookie === null) {
        // null cookie (i.e. no cookie) is acceptable
    } else if (Buffer.isBuffer(cookie) === false) {
        // cookie must be a Buffer (if it is not null)
        throw new TypeError();
    } else if (cookie.length === 0) {
        // zero-length cookies not allowed; pass null as the argument instead
        throw new RangeError();
    } else if (cookie.length > enums.getMaximumCookieLength(serverVersion)) {
        // cookie length may not exceed the maximum length allowed for the specified DTLS version
        throw new RangeError();
    }

    // create and initialize the new HelloVerifyRequestMessage object
    let result = new HelloVerifyRequestMessage();
    // serverVersion
    result.serverVersion = serverVersion;
    // cookie (NOTE: copied from passed-in buffer; we do this so that changes to the original Buffer do not modify our copy and vice-versa)
    if (cookie === null) {
        result.cookie = null;
    } else {
        result.cookie = Buffer.alloc(cookie.length);
        cookie.copy(result.cookie);
    }
    
    // return the new HelloVerifyRequestMessage object
    return result;
}

/**
 * Parses the HelloVerifyRequest message contained in the input Buffer; returns a tuple containing the parsed message ('message') as a HelloVerifyRequestMessage and the bytes consumed ('bytesConsumed') as a whole number.
 * @param {Buffer} buffer - The input buffer containing the HelloVerifyRequest message
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
            
    // create the new HelloVerifyRequestMessage object
    let result = new HelloVerifyRequestMessage();

    // parse buffer
    //
    // serverVersion
    result.serverVersion = buffer.readUInt16BE(currentOffset);
    currentOffset += 2;
    // cookie length
    if (buffer.length - currentOffset < 1) {
        // if the buffer is not big enough, return null
        return null;                
    }
    let cookieLength = buffer[currentOffset];
    currentOffset += 1;
    // cookie (if cookieLength > 0)
    if (buffer.length - currentOffset < cookieLength) {
        // if the buffer is not big enough, return null
        return null;        
    }
    if (cookieLength === 0) {
        // NOTE: we set the cookie to a null pointer, rather than a zero-length buffer
        result.cookie = null;
    } else {
        result.cookie = Buffer.alloc(cookieLength);
        buffer.copy(result.cookie, 0, currentOffset, currentOffset + cookieLength);
        currentOffset += cookieLength;
    }

    // return the new HelloVerifyRequestMessage object
    return {message: result, bytesConsumed: currentOffset - initialOffset};
}

/**
  * Returns a Buffer consisting of the HelloVerifyRequestMessage
  */
HelloVerifyRequestMessage.prototype.toBuffer = function() {
    // validate the object instance's fields
    //
    // serverVersion
    if (!enums.isDtlsVersionValid(this.serverVersion)) {
        throw new RangeError();
    }
    // cookie
    if (this.cookie === null) {
        // null cookie (i.e. no cookie) is acceptable
    } else if (Buffer.isBuffer(this.cookie) === false) {
        // cookie must be a Buffer (if it is not null)
        throw new TypeError();
    } else if (this.cookie.length === 0) {
        // zero-length cookies not allowed; set to null instead
        throw new RangeError();
    } else if (this.cookie.length > enums.getMaximumCookieLength(this.serverVersion)) {
        // cookie length may not exceed the maximum length allowed for the specified DTLS version
        throw new RangeError();
    }
    
    // calculate the length of our buffer
    let bufferLength = 0;
    bufferLength += 2; // Version
    bufferLength += 1; // Cookie Length
    // cookie is optional and will be null if none exists
    if (this.cookie != null)
    {
        bufferLength += this.cookie.length;
    }
    
    // create our buffer (which we will then populate)
    let result = Buffer.alloc(bufferLength);
    // use currentOffset to track the current offset while writing to the buffer    
    let currentOffset = 0;

    // populate the result buffer
    //
    // serverVersion
    result.writeUInt16BE(this.serverVersion, currentOffset);
    currentOffset += 2;
    // cookie length and cookie
    if (this.cookie === null)
    {
        // cookieLength
        result[currentOffset] = 0;
        currentOffset += 1;
        // cookie (no data)
    }
    else
    {
        // cookieLength
        let cookieLength = this.cookie.length;
        result[currentOffset] = cookieLength;
        currentOffset += 1;
        // cookie
        this.cookie.copy(result, currentOffset);
        currentOffset += cookieLength;
    }

    // return the buffer (result)
    return result;
}
