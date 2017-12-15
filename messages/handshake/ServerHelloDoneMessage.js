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
let SerializationHelper = require('../../helpers/SerializationHelper.js');

// constants
const MIN_LENGTH = 0;

function ServerHelloDoneMessage() {
}

/**
 * Returns a new ServerHelloDoneMessage
 */
exports.create = function() {
    // validate inputs
    //
    // [no inputs]

    // create and initialize the new ServerHelloDoneMessage object
    let result = new ServerHelloDoneMessage();

    // return the new ServerHelloDoneMessage object
    return result;
}

/**
 * Parses the ServerHelloDone message contained in the input Buffer; returns a tuple containing the parsed message ('message') as a ServerHelloDoneMessage and the bytes consumed ('bytesConsumed') as a whole number.
 * @param {Buffer} buffer - The input buffer containing the ServerHelloDone message
 * @param {number} offset=0 - The byte-offset within the buffer at which to start parsing
 */
// NOTE: this function returns null if a complete message could not be parsed (and does not validate any data in the returned message); it can also throw an error if the supplied arguments are invalid
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
    
    // create the new ServerHelloDoneMessage object
    let result = new ServerHelloDoneMessage();

    // parse buffer
    //
    // [no content]

    // return the new ServerHelloDoneMessage object
    return {message: result, bytesConsumed: currentOffset - initialOffset};
}

/**
  * Returns a Buffer consisting of the ServerHelloDoneMessage
 */
ServerHelloDoneMessage.prototype.toBuffer = function() {
    // calculate the length of our buffer
    let bufferLength = 0;
    
    // create our buffer (which we will then populate)
    let result = Buffer.alloc(bufferLength);
    // use currentOffset to track the current offset while writing to the buffer    
    let currentOffset = 0;

    // populate the result buffer
    //
    // [no content]

    // return the buffer (result)
    return result;
}
