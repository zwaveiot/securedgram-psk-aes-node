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

let test = require('tape');
//
let enums = require('../../../enums.js');
//
let PskClientKeyExchangeMessage = require('../../../messages/handshake/PskClientKeyExchangeMessage.js');

// constants
const MAX_IDENTITY_LENGTH = (1 << 16) - 1;

exports.testAll = function(t) {
    // test the handling of invalid arguments
    t.test('PskClientKeyExchangeMessage invalid arguments tests', function(st) {
        // generic result variable
        var result;
        // input test variables
        var identity;

        // test an identity which is of an invalid type (we will use null, but it could be anything other than Buffer)
        identity = null;
        try {
            result = PskClientKeyExchangeMessage.create(identity);
            // we should not reach the following line of code!
            st.fail('"identity is not the correct type" test did not throw required exception');
        } catch(e) {
            if (e instanceof TypeError) {
                st.pass('"identity is not the correct type" test threw correct error');
            } else {
                st.fail('"identity is not the correct type" test failed with unknown error');
            }
        }

        // test an identity which is a Buffer but is too long
        identity = Buffer.alloc(MAX_IDENTITY_LENGTH + 1); // an identity which is one byte too long
        try {
            result = PskClientKeyExchangeMessage.create(identity);
            // we should not reach the following line of code!
            st.fail('"identity (a Buffer) is not the correct length" test did not throw required exception');
        } catch(e) {
            if (e instanceof RangeError) {
                st.pass('"identity (a Buffer) is not the correct length" test threw correct error');
            } else {
                st.fail('"identity (a Buffer) is not the correct length" test failed with unknown error');
            }
        }

        // tests have concluded
        st.end();
    });

    // test the handling of invalid fields during serialization
    t.test('PskClientKeyExchangeMessage deserialization invalid fields test', function(st) {
        // generic result variable
        var result;
        // testObject
        var testObject
        // serialized referenceObject
        let serializedReferenceObject = Buffer.from([0x00, 0x10, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F]);

        // test an identity which is of an invalid type (we will use null, but it could be anything other than Buffer)
        //
        // deserialize an object from our serializedReferenceObject
        testObject = PskClientKeyExchangeMessage.fromBuffer(serializedReferenceObject).message;
        // modify the identity parameter
        testObject.identity = null;
        // attempt to re-serialize the object
        try {
            result = testObject.toBuffer();
            // we should not reach the following line of code!
            st.fail('"identity is not the correct type" test did not throw required exception');
        } catch(e) {
            if (e instanceof TypeError) {
                st.pass('"identity is not the correct type" test threw correct error');
            } else {
                st.fail('"identity is not the correct type" test failed with unknown error');
            }
        }

        // test an identity which is a Buffer but is too long
        //
        // deserialize an object from our serializedReferenceObject
        testObject = PskClientKeyExchangeMessage.fromBuffer(serializedReferenceObject).message;
        // modify the identity parameter
        testObject.identity = Buffer.alloc(MAX_IDENTITY_LENGTH + 1); // an identity which is one byte too long
        try {
            result = testObject.toBuffer();
            // we should not reach the following line of code!
            st.fail('"identity (a Buffer) is not the correct length" test did not throw required exception');
        } catch(e) {
            if (e instanceof RangeError) {
                st.pass('"identity (a Buffer) is not the correct length" test threw correct error');
            } else {
                st.fail('"identity (a Buffer) is not the correct length" test failed with unknown error');
            }
        }
        
        // tests have concluded
        st.end();
    });
    
    // test serialization + deserialization (typical contents)
    t.test('PskClientKeyExchangeMessage serialization + deserialization test (typical contents)', function(st) {
        // populate input data for a PskClientKeyExchangeMessage object
        //
        // identity
        let identity = Buffer.from([0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F]);
        //
        // create a PskClientKeyExchangeMessage object
        let originalObject = PskClientKeyExchangeMessage.create(identity);

        // verify that our arguments were successfully stored by the create function
        //
        // identity
        st.ok(identity.equals(originalObject.identity), 'identity argument stored');

        // verify that our original arguments do not share references with the originalObject's stored copies.
        //
        // identity
        // step 1: modify the original buffer
        identity[0] += 1;
        // step 2: make sure that the two buffers now no longer match
        st.notOk(identity.equals(originalObject.identity), 'identity argument copied');

        // convert the originalObject into a Buffer
        let serializedBuffer = originalObject.toBuffer();

        // verify that the serialized Buffer matches the expected value
        let toBufferExpectedResult = Buffer.from([0x00, 0x10, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F]);
        st.ok(toBufferExpectedResult.equals(serializedBuffer), 'serialization returned the expected result');
        
        // deserialize the serialized Buffer into a new object (for roundtrip equality comparison)
        let fromBufferResult = PskClientKeyExchangeMessage.fromBuffer(serializedBuffer);
        let verifyObject = fromBufferResult.message;
        let bytesConsumed = fromBufferResult.bytesConsumed;

        // verify that the deserialization of verifyObject consumed all bytes in the Buffer
        st.equal(bytesConsumed, serializedBuffer.length, 'deserialization consumed all bytes')
        
        // make sure that the verifyObject is not null (i.e. that deserialization did not fail)
        st.notEqual(verifyObject, null, 'deserialized object is not null');

        // now verify that the originalObject and the verifyObject are identical
        //
        // identity
        st.ok(originalObject.identity.equals(verifyObject.identity), 'deserialized identity contents matches');

        // tests have concluded
        st.end();
    });

}