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

'use script';

/* Record layout:
 *      00: MessageType
 *      01: Length MSB
 *      02: Length (continued)
 *      03: Length LSB
 *      04: Message Sequence MSB
 *      05: Message Sequence LSB
 *      06: Fragment Offset MSB
 *      07: Fragment Offset (continued)
 *      08: Fragment Offset LSB
 *      09: Fragment Length MSB
 *      10: Fragment Length (continued)
 *      11: Fragment Length LSB
 *     12+: Message
 */

let enums = require('../enums.js');

// constants
const HEADER_LENGTH = 12;
//
const MAX_LENGTH = (1 << 24) - 1;
const MAX_FRAGMENT_OFFSET = (1 << 24) - 1;
const MAX_FRAGMENT_LENGTH = (1 << 24) - 1;

function DtlsHandshakeRecord() {
    this.messageType = null;
    this.length = null;
    this.messageSequence = null; // 16 bit (handshake sequence # which does not change during retransmission/fragmentation, not to be confused with the session's underlying epoch+sequenceNumber combination which must generate a new number during transmission)
    this.fragmentOffset = null;  // 24 bit
    this.fragmentLength = null;  // 24 bit
    this.message = null;
}

exports.createFromMessageBuffer = function(type, length, messageSequence, fragmentOffset, fragmentLength, messageBuffer) {
    // validate inputs
    //
    // type
    if (!enums.isMessageTypeValid(type)) {
        throw new RangeError();
    }
    // length
    // note: all positive integers up to (2^24)-1 are valid for length
    if (typeof length !== "number") {
        throw new TypeError();
    } else if ((length < 0) || (length > MAX_LENGTH) || (Math.floor(length) != length)) {
        throw new RangeError();
    }
    // messageSequence
    // note: all positive integers up to (2^16)-1 are valid for messageSequence
    if (typeof messageSequence !== "number") {
        throw new TypeError();
    } else if ((messageSequence < 0) || (messageSequence > Math.pow(2, 16) - 1) || (Math.floor(messageSequence) != messageSequence)) {
        throw new RangeError();
    }
    // fragmentOffset
    // note: all positive integers up to (2^24)-1 are valid for fragmentOffset
    if (typeof fragmentOffset !== "number") {
        throw new TypeError();
    } else if ((fragmentOffset < 0) || (fragmentOffset > MAX_FRAGMENT_OFFSET) || (Math.floor(fragmentOffset) != fragmentOffset)) {
        throw new RangeError();
    }
    // fragmentLength
    // note: all positive integers up to (2^24)-1 are valid for fragmentLength
    if (typeof fragmentLength !== "number") {
        throw new TypeError();
    } else if ((fragmentLength < 0) || (fragmentLength > MAX_FRAGMENT_LENGTH) || (Math.floor(fragmentLength) != fragmentLength)) {
        throw new RangeError();
    }
    // messageBuffer
    if (Object.prototype.toString.call(messageBuffer) != "[object Uint8Array]") {
        throw new TypeError();
    } else if (messageBuffer.length > MAX_FRAGMENT_LENGTH) {
        throw new RangeError();
    } else if (messageBuffer.length < fragmentLength) {
        throw new RangeError();
    }
    // also validate that our total length is at least as large as the fragmentOffset + fragmentLength
    if (length < fragmentOffset + fragmentLength)
    {
        throw new RangeError();
    }

    // create and initialize the new DtlsHandshake record object
    let result = new DtlsHandshakeRecord();
    result.length = length;
    result.messageType = type;
    result.messageSequence = messageSequence;
    result.fragmentOffset = fragmentOffset;
    result.fragmentLength = fragmentLength;
    result.message = messageBuffer;

    // return the new DtlsHandshake record object
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
    } else if (buffer.length - currentOffset < HEADER_LENGTH) {
        // buffer is not long enough for a full record; return null.
        return null;
    }
    
    // create the new DtlsHandshakeRecord object
    let result = new DtlsHandshakeRecord();

    // parse buffer
    //
    // type (octet 0)
    result.messageType = buffer[currentOffset];
    currentOffset += 1;
    // length (octets 1-3)
    result.length = buffer.readUIntBE(currentOffset, 3);
    currentOffset += 3;
    // messageSequence (octets 4-5)
    result.messageSequence = buffer.readUInt16BE(currentOffset);
    currentOffset += 2;
    // fragmentOffset (octets 6-8)
    result.fragmentOffset = buffer.readUIntBE(currentOffset, 3);
    currentOffset += 3;
    // fragmentLength (octets 9-11)
    result.fragmentLength = buffer.readUIntBE(currentOffset, 3);
    currentOffset += 3;
    // verify that the buffer length is long enough to fit the message
    if (buffer.length - currentOffset < result.fragmentLength) {
        // if the buffer is not big enough, return null
        return null;
    }
    // message
    result.message = Buffer.alloc(result.fragmentLength);
    buffer.copy(result.message, 0, currentOffset, currentOffset + result.fragmentLength);
    currentOffset += result.fragmentLength;

    // return the new DtlsHandshakeRecord object
    return {record: result, bytesConsumed: currentOffset - initialOffset};
}

DtlsHandshakeRecord.prototype.toBuffer = function() {
    // create our buffer (which we will then populate)
    let result = Buffer.alloc(HEADER_LENGTH + this.message.length);
    // use offset to track the current offset while writing to the buffer    
    let offset = 0;

    // populate record header
    //
    // type (octet 0)
    result[offset] = this.messageType;
    offset += 1;
    // length (octets 1-3)
    result.writeUIntBE(this.length, offset, 3);
    offset += 3;
    // messageSequence (octets 4-5)
    result.writeUInt16BE(this.messageSequence, offset);
    offset += 2;
    // fragmentOffset (octets 6-8)
    result.writeUIntBE(this.fragmentOffset, offset, 3);
    offset += 3;
    // fragmentLength (octets 9-11)
    result.writeUIntBE(this.fragmentLength, offset, 3);
    offset += 3;
    // message
    this.message.copy(result, offset, 0, this.message.length); 
    offset += this.message.length;

    // return the buffer (result)
    return result;
}