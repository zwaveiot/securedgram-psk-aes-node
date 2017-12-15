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
let FinishedMessage = require('../../../messages/handshake/FinishedMessage.js');

exports.testAll = function(t) {
    // test the handling of invalid arguments
    t.test('FinishedMessage invalid arguments tests', function(st) {
        // generic result variable
        var result;
        // input test variables
        var verifyData;

        // test a verifyData which is of an invalid type (we will use null, but it could be anything other than Buffer)
        verifyData = null;
        try {
            result = FinishedMessage.create(verifyData);
            // we should not reach the following line of code!
            st.fail('"verifyData is not the correct type" test did not throw required exception');
        } catch(e) {
            if (e instanceof TypeError) {
                st.pass('"verifyData is not the correct type" test threw correct error');
            } else {
                st.fail('"verifyData is not the correct type" test failed with unknown error');
            }
        }

        // test a verifyData which is a Buffer but has an invalid length
        verifyData = Buffer.alloc(0);
        try {
            result = FinishedMessage.create(verifyData);
            // we should not reach the following line of code!
            st.fail('"verifyData (a Buffer) is not the correct length" test did not throw required exception');
        } catch(e) {
            if (e instanceof RangeError) {
                st.pass('"verifyData (a Buffer) is not the correct length" test threw correct error');
            } else {
                st.fail('"verifyData (a Buffer) is not the correct length" test failed with unknown error');
            }
        }

        // tests have concluded
        st.end();
    });

    // test the handling of invalid fields during serialization
    t.test('FinishedMessage deserialization invalid fields test', function(st) {
        // generic result variable
        var result;
        // testObject
        var testObject
        // serialized referenceObject
        let serializedReferenceObject = Buffer.from([0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F]);

        // test a verifyData which is of an invalid type (we will use null, but it could be anything other than Buffer)
        //
        // deserialize an object from our serializedReferenceObject
        testObject = FinishedMessage.fromBuffer(serializedReferenceObject).message;
        // modify the verifyData parameter
        testObject.verifyData = null;
        // attempt to re-serialize the object
        try {
            result = testObject.toBuffer();
            // we should not reach the following line of code!
            st.fail('"verifyData is not the correct type" test did not throw required exception');
        } catch(e) {
            if (e instanceof TypeError) {
                st.pass('"verifyData is not the correct type" test threw correct error');
            } else {
                st.fail('"verifyData is not the correct type" test failed with unknown error');
            }
        }

        // test a verifyData which is a Buffer but has an invalid length
        //
        // deserialize an object from our serializedReferenceObject
        testObject = FinishedMessage.fromBuffer(serializedReferenceObject).message;
        // modify the verifyData parameter
        testObject.verifyData = Buffer.alloc(0);
        try {
            result = testObject.toBuffer();
            // we should not reach the following line of code!
            st.fail('"verifyData (a Buffer) is not the correct length" test did not throw required exception');
        } catch(e) {
            if (e instanceof RangeError) {
                st.pass('"verifyData (a Buffer) is not the correct length" test threw correct error');
            } else {
                st.fail('"verifyData (a Buffer) is not the correct length" test failed with unknown error');
            }
        }
        
        // tests have concluded
        st.end();
    });
    
    // test serialization + deserialization
    t.test('FinishedMessage serialization + deserialization test', function(st) {
        // populate input data for a FinishedMessage object
        //
        // verifyData
        let verifyData = Buffer.from([0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F]);
        //
        // create a FinishedMessage object
        let originalObject = FinishedMessage.create(verifyData);

        // verify that our arguments were successfully stored by the create function
        //
        // verifyData
        st.ok(verifyData.equals(originalObject.verifyData), 'verifyData argument stored');

        // verify that our original arguments do not share references with the originalObject's stored copies.
        //
        // verifyData
        // step 1: modify the original buffer
        verifyData[0] += 1;
        // step 2: make sure that the two buffers now no longer match
        st.notOk(verifyData.equals(originalObject.verifyData), 'verifyData argument copied');

        // convert the originalObject into a Buffer
        let serializedBuffer = originalObject.toBuffer();

        // verify that the serialized Buffer matches the expected value
        let toBufferExpectedResult = Buffer.from([0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F]);
        st.ok(toBufferExpectedResult.equals(serializedBuffer), 'serialization returned the expected result');
        
        // deserialize the serialized Buffer into a new object (for roundtrip equality comparison)
        let fromBufferResult = FinishedMessage.fromBuffer(serializedBuffer);
        let verifyObject = fromBufferResult.message;
        let bytesConsumed = fromBufferResult.bytesConsumed;

        // verify that the deserialization of verifyObject consumed all bytes in the Buffer
        st.equal(bytesConsumed, serializedBuffer.length, 'deserialization consumed all bytes')
        
        // make sure that the verifyObject is not null (i.e. that deserialization did not fail)
        st.notEqual(verifyObject, null, 'deserialized object is not null');

        // now verify that the originalObject and the verifyObject are identical
        //
        // verifyData
        st.ok(originalObject.verifyData.equals(verifyObject.verifyData), 'deserialized verifyData contents matches');

        // tests have concluded
        st.end();
    });

}