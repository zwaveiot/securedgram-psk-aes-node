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
let HelloVerifyRequestMessage = require('../../../messages/handshake/HelloVerifyRequestMessage.js');

exports.testAll = function(t) {
    // test the handling of invalid arguments
    t.test('HelloVerifyRequestMessage invalid arguments tests', function(st) {
        // generic result variable
        var result;
        // input test variables
        var serverVersion;
        var cookie;

        // test a serverVersion which is invalid (we will use null, but it could be anything other than a valid DtlsVersion value)
        serverVersion = null;
        cookie = null; // for this test we will pass in a null cookie -- to make sure that we are not triggering the RangeError due to an invalid cookie
        try {
            result = HelloVerifyRequestMessage.create(serverVersion, cookie);
            // we should not reach the following line of code!
            st.fail('"serverVersion is not valid" test did not throw required exception');
        } catch(e) {
            if (e instanceof RangeError) {
                st.pass('"serverVersion is not valid" test threw correct error');
            } else {
                st.fail('"serverVersion is not valid" test failed with unknown error');
            }
        }

        // test a cookie which is of an invalid type (we will use a number, but it could be anything other than Buffer or null)
        serverVersion = enums.DtlsVersion.DTLS_1_0;
        cookie = 1; // invalid type 'number'
        try {
            result = HelloVerifyRequestMessage.create(serverVersion, cookie);
            // we should not reach the following line of code!
            st.fail('"cookie is not the correct type" test did not throw required exception');
        } catch(e) {
            if (e instanceof TypeError) {
                st.pass('"cookie is not the correct type" test threw correct error');
            } else {
                st.fail('"cookie is not the correct type" test failed with unknown error');
            }
        }

        // test a cookie which is a Buffer but is zero bytes in length; callers may pass in either null or a non-empty Buffer
        serverVersion = enums.DtlsVersion.DTLS_1_0;
        cookie = Buffer.alloc(0); // "empty" cookie (which is not allowed)
        try {
            result = HelloVerifyRequestMessage.create(serverVersion, cookie);
            // we should not reach the following line of code!
            st.fail('"cookie (a Buffer) is zero-length" test did not throw required exception');
        } catch(e) {
            if (e instanceof RangeError) {
                st.pass('"cookie (a Buffer) is zero-length" test threw correct error');
            } else {
                st.fail('"cookie (a Buffer) is zero-length" test failed with unknown error');
            }
        }
        
        // test a cookie which is a Buffer but is too long
        serverVersion = enums.DtlsVersion.DTLS_1_0;
        cookie = Buffer.alloc(enums.getMaximumCookieLength(serverVersion) + 1); // a cookie which is one byte too long
        try {
            result = HelloVerifyRequestMessage.create(serverVersion, cookie);
            // we should not reach the following line of code!
            st.fail('"cookie (a Buffer) is not the correct length" test did not throw required exception');
        } catch(e) {
            if (e instanceof RangeError) {
                st.pass('"cookie (a Buffer) is not the correct length" test threw correct error');
            } else {
                st.fail('"cookie (a Buffer) is not the correct length" test failed with unknown error');
            }
        }

        // tests have concluded
        st.end();
    });

    // test the handling of invalid fields during serialization
    t.test('HelloVerifyRequestMessage deserialization invalid fields test', function(st) {
        // generic result variable
        var result;
        // testObject
        var testObject
        // serialized referenceObject
        let serializedReferenceObject = Buffer.from([0xFE, 0xFF, 0x20, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        // test a serverVersion which is invalid (we will use null, but it could be anything other than a valid DtlsVersion value)
        //
        // deserialize an object from our serializedReferenceObject
        testObject = HelloVerifyRequestMessage.fromBuffer(serializedReferenceObject).message;
        // modify the serverVersion parameter
        testObject.serverVersion = null;
        // attempt to re-serialize the object
        try {
            result = testObject.toBuffer();
            // we should not reach the following line of code!
            st.fail('"serverVersion is not valid" test did not throw required exception');
        } catch(e) {
            if (e instanceof RangeError) {
                st.pass('"serverVersion is not valid" test threw correct error');
            } else {
                st.fail('"serverVersion is not valid" test failed with unknown error');
            }
        }

        // test a cookie which is of an invalid type (we will use a number, but it could be anything other than Buffer or null)
        //
        // deserialize an object from our serializedReferenceObject
        testObject = HelloVerifyRequestMessage.fromBuffer(serializedReferenceObject).message;
        // modify the cookie parameter
        testObject.cookie = 1; // invalid type 'number'
        try {
            result = testObject.toBuffer();
            // we should not reach the following line of code!
            st.fail('"cookie is not the correct type" test did not throw required exception');
        } catch(e) {
            if (e instanceof TypeError) {
                st.pass('"cookie is not the correct type" test threw correct error');
            } else {
                st.fail('"cookie is not the correct type" test failed with unknown error');
            }
        }
        
        // test a cookie which is a Buffer but is zero bytes in length; callers may pass in either null or a non-empty Buffer
        //
        // deserialize an object from our serializedReferenceObject
        testObject = HelloVerifyRequestMessage.fromBuffer(serializedReferenceObject).message;
        // modify the cookie parameter
        testObject.cookie = Buffer.alloc(0); // "empty" cookie (which is not allowed)
        try {
            result = testObject.toBuffer();
            // we should not reach the following line of code!
            st.fail('"cookie (a Buffer) is zero-length" test did not throw required exception');
        } catch(e) {
            if (e instanceof RangeError) {
                st.pass('"cookie (a Buffer) is zero-length" test threw correct error');
            } else {
                st.fail('"cookie (a Buffer) is zero-length" test failed with unknown error');
            }
        }
        
        // test a cookie which is a Buffer but is too long
        //
        // deserialize an object from our serializedReferenceObject
        testObject = HelloVerifyRequestMessage.fromBuffer(serializedReferenceObject).message;
        // modify the cookie parameter
        testObject.cookie = Buffer.alloc(enums.getMaximumCookieLength(testObject.serverVersion) + 1); // a cookie which is one byte too long
        try {
            result = testObject.toBuffer();
            // we should not reach the following line of code!
            st.fail('"cookie (a Buffer) is not the correct length" test did not throw required exception');
        } catch(e) {
            if (e instanceof RangeError) {
                st.pass('"cookie (a Buffer) is not the correct length" test threw correct error');
            } else {
                st.fail('"cookie (a Buffer) is not the correct length" test failed with unknown error');
            }
        }
        
        // tests have concluded
        st.end();
    });

    // test serialization + deserialization (typical contents)
    t.test('HelloVerifyRequestMessage serialization + deserialization test (typical contents)', function(st) {
        // populate input data for a HelloVerifyRequestMessage object
        //
        // serverVersion
        let serverVersion = enums.DtlsVersion.DTLS_1_0;
        // cookie
        let cookie = Buffer.from([0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        //
        // create a HelloVerifyRequestMessage object
        let originalObject = HelloVerifyRequestMessage.create(serverVersion, cookie);

        // verify that our arguments were successfully stored by the create function
        //
        // serverVersion
        st.ok(serverVersion === originalObject.serverVersion, 'serverVersion argument stored');        
        // cookie
        st.ok(cookie.equals(originalObject.cookie), 'cookie argument stored');

        // verify that our original arguments do not share references with the originalObject's stored copies.
        //
        // cookie
        // step 1: modify the original buffer
        cookie[0] += 1;
        // step 2: make sure that the two buffers now no longer match
        st.notOk(cookie.equals(originalObject.cookie), 'cookie argument copied');

        // convert the originalObject into a Buffer
        let serializedBuffer = originalObject.toBuffer();

        // verify that the serialized Buffer matches the expected value
        let toBufferExpectedResult = Buffer.from([0xFE, 0xFF, 0x20, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        st.ok(toBufferExpectedResult.equals(serializedBuffer), 'serialization returned the expected result');
        
        // deserialize the serialized Buffer into a new object (for roundtrip equality comparison)
        let fromBufferResult = HelloVerifyRequestMessage.fromBuffer(serializedBuffer);
        let verifyObject = fromBufferResult.message;
        let bytesConsumed = fromBufferResult.bytesConsumed;

        // verify that the deserialization of verifyObject consumed all bytes in the Buffer
        st.equal(bytesConsumed, serializedBuffer.length, 'deserialization consumed all bytes')
        
        // make sure that the verifyObject is not null (i.e. that deserialization did not fail)
        st.notEqual(verifyObject, null, 'deserialized object is not null');

        // now verify that the originalObject and the verifyObject are identical
        //
        // serverVersion
        st.ok(originalObject.serverVersion === verifyObject.serverVersion, 'deserialized serverVersion contents matches');
        // cookie
        st.ok(originalObject.cookie.equals(verifyObject.cookie), 'deserialized cookie contents matches');

        // tests have concluded
        st.end();
    });

    // test serialization + deserialization (undefined cookie)
    t.test('HelloVerifyRequestMessage serialization + deserialization test (undefined cookie)', function(st) {
        // populate input data for a HelloVerifyRequestMessage object
        //
        // serverVersion
        let serverVersion = enums.DtlsVersion.DTLS_1_0;
        // cookie
        let cookie = undefined;
        //
        // create a HelloVerifyRequestMessage object
        let originalObject = HelloVerifyRequestMessage.create(serverVersion, cookie);

        // verify that our cookie argument was successfully stored (default value of null) by the create function
        //
        // serverVersion
        st.ok(serverVersion === originalObject.serverVersion, 'serverVersion argument stored');        
        // cookie
        st.ok(originalObject.cookie === null, 'cookie argument stored');

        // verify that our original arguments do not share references with the originalObject's stored copies.
        // [not applicable]

        // convert the originalObject into a Buffer
        let serializedBuffer = originalObject.toBuffer();

        // verify that the serialized Buffer matches the expected value
        let toBufferExpectedResult = Buffer.from([0xFE, 0xFF, 0x00]);
        st.ok(toBufferExpectedResult.equals(serializedBuffer), 'serialization returned the expected result');
        
        // deserialize the serialized Buffer into a new object (for roundtrip equality comparison)
        let fromBufferResult = HelloVerifyRequestMessage.fromBuffer(serializedBuffer);
        let verifyObject = fromBufferResult.message;
        let bytesConsumed = fromBufferResult.bytesConsumed;

        // verify that the deserialization of verifyObject consumed all bytes in the Buffer
        st.equal(bytesConsumed, serializedBuffer.length, 'deserialization consumed all bytes')
        
        // make sure that the verifyObject is not null (i.e. that deserialization did not fail)
        st.notEqual(verifyObject, null, 'deserialized object is not null');

        // now verify that the originalObject and the verifyObject are identical
        //
        // serverVersion
        st.ok(originalObject.serverVersion === verifyObject.serverVersion, 'deserialized serverVersion contents matches');
        // cookie
        st.ok(originalObject.cookie === verifyObject.cookie, 'deserialized cookie contents matches');

        // tests have concluded
        st.end();
    });

    // test serialization + deserialization (null cookie)
    t.test('HelloVerifyRequestMessage serialization + deserialization test (null cookie)', function(st) {
        // populate input data for a HelloVerifyRequestMessage object
        //
        // serverVersion
        let serverVersion = enums.DtlsVersion.DTLS_1_0;
        // cookie
        let cookie = null;
        //
        // create a HelloVerifyRequestMessage object
        let originalObject = HelloVerifyRequestMessage.create(serverVersion, cookie);

        // verify that our cookie argument was successfully stored by the create function
        //
        // serverVersion
        st.ok(serverVersion === originalObject.serverVersion, 'serverVersion argument stored');        
        // cookie
        st.ok(originalObject.cookie === null, 'cookie argument stored');

        // verify that our original arguments do not share references with the originalObject's stored copies.
        // [not applicable]

        // convert the originalObject into a Buffer
        let serializedBuffer = originalObject.toBuffer();

        // verify that the serialized Buffer matches the expected value
        let toBufferExpectedResult = Buffer.from([0xFE, 0xFF, 0x00]);
        st.ok(toBufferExpectedResult.equals(serializedBuffer), 'serialization returned the expected result');
        
        // deserialize the serialized Buffer into a new object (for roundtrip equality comparison)
        let fromBufferResult = HelloVerifyRequestMessage.fromBuffer(serializedBuffer);
        let verifyObject = fromBufferResult.message;
        let bytesConsumed = fromBufferResult.bytesConsumed;

        // verify that the deserialization of verifyObject consumed all bytes in the Buffer
        st.equal(bytesConsumed, serializedBuffer.length, 'deserialization consumed all bytes')
        
        // make sure that the verifyObject is not null (i.e. that deserialization did not fail)
        st.notEqual(verifyObject, null, 'deserialized object is not null');

        // now verify that the originalObject and the verifyObject are identical
        //
        // serverVersion
        st.ok(originalObject.serverVersion === verifyObject.serverVersion, 'deserialized serverVersion contents matches');
        // cookie
        st.ok(originalObject.cookie === verifyObject.cookie, 'deserialized cookie contents matches');

        // tests have concluded
        st.end();
    });   

}