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
let SerializationHelper = require('../../helpers/SerializationHelper.js');

exports.testAll = function(t) {
    // test ValidateDeserializationArguments function
    t.test('ValidateDeserializationArguments tests', function(st) {
        let buffer;
        let offset;
        let minimumLength;
        let result;

        // test an undefined buffer; this should throw a TypeError
        buffer = undefined;
        offset = 0;
        minimumLength = 0;
        try {
            result = SerializationHelper.ValidateDeserializationArguments(buffer, offset, minimumLength);
            // we should not reach the following line of code!
            st.fail('"buffer = undefined" test did not throw required exception');
        } catch(e) {
            if (e instanceof TypeError) {
                st.pass('"buffer = undefined" test threw correct error');
            } else {
                st.fail('"buffer = undefined" test failed with unknown error');
            }
        }

        // test a buffer which is of an invalid type (we will use null, but it could be anything other than Buffer)
        buffer = null;
        offset = 0;
        minimumLength = 0;
        try {
            result = SerializationHelper.ValidateDeserializationArguments(buffer, offset, minimumLength);
            // we should not reach the following line of code!
            st.fail('"buffer is not the correct type" test did not throw required exception');
        } catch(e) {
            if (e instanceof TypeError) {
                st.pass('"buffer is not the correct type" test threw correct error');
            } else {
                st.fail('"buffer is not the correct type" test failed with unknown error');
            }
        }

        // test a null offset; this should succeed
        buffer = Buffer.alloc(0);
        offset = undefined;
        minimumLength = 0;
        try {
            result = SerializationHelper.ValidateDeserializationArguments(buffer, offset, minimumLength);
            if(result === true) {
                st.pass('"offset = null" test passed');
            } else {
                st.pass('"offset = null" test returned the incorrect result');
            }
        } catch(e) {
            // we should not reach the following line of code!
            st.fail('"offset = null" test should not have thrown an exception');
        }

        // test an offset which is of an invalid type (we will use null, but it could be anything other than number)
        buffer = Buffer.alloc(0);
        offset = null;
        minimumLength = 0;
        try {
            result = SerializationHelper.ValidateDeserializationArguments(buffer, offset, minimumLength);
            // we should not reach the following line of code!
            st.fail('"offset is not the correct type" test did not throw required exception');
        } catch(e) {
            if (e instanceof TypeError) {
                st.pass('"offset is not the correct type" test threw correct error');
            } else {
                st.fail('"offset is not the correct type" test failed with unknown error');
            }
        }

        // test a negative offset; this should return an error
        buffer = Buffer.alloc(0);
        offset = -1;
        minimumLength = 0;
        try {
            result = SerializationHelper.ValidateDeserializationArguments(buffer, offset, minimumLength);
            // we should not reach the following line of code!
            st.fail('"offset is negative" test did not throw required exception');
        } catch(e) {
            if (e instanceof RangeError) {
                st.pass('"offset is negative" test threw correct error');
            } else {
                st.fail('"offset is negative" test failed with unknown error');
            }
        }

        // test a beyond-upper-bound offset; this should return an error
        buffer = Buffer.alloc(0);
        offset = 1;
        minimumLength = 0;
        try {
            result = SerializationHelper.ValidateDeserializationArguments(buffer, offset, minimumLength);
            // we should not reach the following line of code!
            st.fail('"offset is beyond the end of the Buffer" test did not throw required exception');
        } catch(e) {
            if (e instanceof RangeError) {
                st.pass('"offset is beyond the end of the Buffer" test threw correct error');
            } else {
                st.fail('"offset is beyond the end of the Buffer" test failed with unknown error');
            }
        }

        // test an undefined (or otherwise invalidly typed) minimumLength; this should throw a TypeError
        buffer = Buffer.alloc(0);
        offset = 0;
        minimumLength = undefined;
        try {
            result = SerializationHelper.ValidateDeserializationArguments(buffer, offset, minimumLength);
            // we should not reach the following line of code!
            st.fail('"minimumLength = undefined" test did not throw required exception');
        } catch(e) {
            if (e instanceof TypeError) {
                st.pass('"minimumLength = undefined" test threw correct error');
            } else {
                st.fail('"minimumLength = undefined" test failed with unknown error');
            }
        }
        
        // test a negative minimumLength; this should return an error
        buffer = Buffer.alloc(0);
        offset = 0;
        minimumLength = -1;
        try {
            result = SerializationHelper.ValidateDeserializationArguments(buffer, offset, minimumLength);
            // we should not reach the following line of code!
            st.fail('"minimumLength is negative" test did not throw required exception');
        } catch(e) {
            if (e instanceof RangeError) {
                st.pass('"minimumLength is negative" test threw correct error');
            } else {
                st.fail('"minimumLength is negative" test failed with unknown error');
            }
        }

        // test a buffer which is too small for the minimum deserialization; this should return "false"
        buffer = Buffer.alloc(0);
        offset = 0;
        minimumLength = 1;
        try {
            result = SerializationHelper.ValidateDeserializationArguments(buffer, offset, minimumLength);
            if(result === false) {
                st.pass('"buffer is not large enough" test passed');
            } else {
                st.pass('"buffer is not large enough" test returned the incorrect result');
            }
        } catch(e) {
            // we should not reach the following line of code!
            st.fail('"buffer is not large enough" test should not have thrown an exception');
        }
        
        // tests have concluded
        st.end();
    });

}