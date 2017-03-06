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

/* ClientKeyExchange message layout:
 *      00: Identity Length (MSB)
 *      01: Identity Length (LSB)
 * .......: Identity
 */

let enums = require('../../enums.js');

// constants

function PskClientKeyExchangeMessage() {
    this.identity = null;
}

exports.create = function(identity) {
    // validate inputs
    //
    // identity
    if (typeof identity === "undefined") {
        throw new TypeError();
    } else if (identity === null) {
        // null identity (i.e. no identity) is acceptable
        // NOTE: after a search of TLS, DTLS and PSK RFCs, no rules could be located which require a non-empty identity value
    } else if (Object.prototype.toString.call(identity) != "[object Uint8Array]") {
        throw new TypeError();
    }

    // create and initialize the new PskClientKeyExchangeMessage object
    let result = new PskClientKeyExchangeMessage();
    result.identity = identity;

    // return the new PskClientKeyExchangeMessage object
    return result;
}

PskClientKeyExchangeMessage.prototype.toBuffer = function() {
    // calculate the length of our buffer
    let bufferLength = 0;
    bufferLength += 2; // Identity Length
    // identity is optional and will be null if none exists
    if (this.identity != null)
    {
        bufferLength += this.identity.length;
    }
    
    // create our buffer (which we will then populate)
    let result = Buffer.alloc(bufferLength);
    // use offset to track the current offset while writing to the buffer    
    let offset = 0;

    // populate message header
    //
    // identity length and identity
    if (this.identity == null)
    {
        result.writeUInt16BE(0, offset);
        offset += 2;
    }
    else
    {
        let identityAsBuffer = new Buffer(this.identity);
        result.writeUInt16BE(identityAsBuffer.length, offset);
        offset += 2;
        identityAsBuffer.copy(result, offset, 0, identityAsBuffer.length);
        offset += identityAsBuffer.length;
    }

    // return the buffer (result)
    return result;
}