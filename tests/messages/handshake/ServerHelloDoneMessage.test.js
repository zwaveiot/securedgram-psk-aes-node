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
let ServerHelloDoneMessage = require('../../../messages/handshake/ServerHelloDoneMessage.js');

exports.testAll = function(t) {
    // test the handling of invalid arguments
    t.test('ServerHelloDoneMessage invalid arguments tests', function(st) {
        st.pass('create function has no arguments; test automatically passed');

        // tests have concluded
        st.end();
    });

    // test the handling of invalid fields during serialization
    t.test('ServerHelloDoneMessage deserialization invalid fields test', function(st) {
        st.pass('object has no fields; test automatically passed');
        
        // tests have concluded
        st.end();
    });
    
    // test serialization + deserialization
    t.test('ServerHelloDoneMessage serialization + deserialization test', function(st) {
        // populate input data for a ServerHelloDoneMessage object
        // [no data]
        //
        // create a ServerHelloDoneMessage object
        let originalObject = ServerHelloDoneMessage.create();

        // verify that our arguments were successfully stored by the create function
        // since there are no contents in this object, pass the "contents match" test automatically
        st.pass('all arguments stored');

        // verify that our original arguments do not share references with the originalObject's stored copies.
        //
        // since there are no contents in this object, pass the "contents match" test automatically
        st.pass('all arguments copied');
                
        // convert the originalObject into a Buffer
        let serializedBuffer = originalObject.toBuffer();

        // verify that the serialized Buffer matches the expected value
        let toBufferExpectedResult = Buffer.from([ /* no contents */ ]);
        st.ok(toBufferExpectedResult.equals(serializedBuffer), 'serialization returned the expected result');
        
        // deserialize the serialized Buffer into a new object (for roundtrip equality comparison)
        let fromBufferResult = ServerHelloDoneMessage.fromBuffer(serializedBuffer);
        let verifyObject = fromBufferResult.message;
        let bytesConsumed = fromBufferResult.bytesConsumed;

        // verify that the deserialization of verifyObject consumed all bytes in the Buffer
        st.equal(bytesConsumed, serializedBuffer.length, 'deserialization consumed all bytes')
        
        // make sure that the verifyObject is not null (i.e. that deserialization did not fail)
        st.notEqual(verifyObject, null, 'deserialized object is not null');

        // now verify that the originalObject and the verifyObject are identical
        //
        // since there are no contents in this object, pass the "contents match" test automatically
        st.pass('deserialized contents all match')

        // tests have concluded
        st.end();
    });

}