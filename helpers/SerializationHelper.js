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

/**
 * Returns true if deserialization arguments are valid; returns false if the buffer is not large enough; throws an exception if they are invalid
 * @param {Buffer} buffer - The input buffer containing the serialized object
 * @param {number} offset=0 - The byte-offset within the buffer at which to start parsing
 * @param {number} minimumLength - The minimum valid length of the serialized object
 */
exports.ValidateDeserializationArguments = function(buffer, offset, minimumLength) {
    // we assume that the arguments are valid unless we find out that they are not.
    let success = true;

    // validate input arguments
    //
    // buffer
    if (typeof buffer === 'undefined') {
        throw new TypeError();
    } else if (Buffer.isBuffer(buffer) === false) {
        // buffer must be a Buffer
        throw new TypeError();
    }
    // minimumLength
    if (typeof minimumLength !== 'number') {
        throw new TypeError();
    } else if (minimumLength < 0) {
        throw new RangeError();
    }
    // offset
    if (typeof offset === 'undefined') {
        // offset is optional; this is allowed; set the local (passed-by-value) variable to zero so that follow-up tests succeed.
        offset = 0;
    } else if (typeof offset !== 'number') {
        // if the offset is provided, but it is not a number, then return an error
        throw new TypeError();
    } else if ((offset < 0) || (offset > buffer.length)) {
        // offset may not be beyond the buffer contents
        throw new RangeError();
    }
    //
    // also validate that the buffer is long enough to hold the minimum serialized content
    if (buffer.length - offset < minimumLength) {
        // buffer is not long enough for a full message; return null.
        success = false;
    }

    // return our result (true = all good; false = programatically valid but arguments do not meet criteria)
    return success;
}