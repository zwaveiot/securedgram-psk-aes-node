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
// helpers
let SerializationHelperTest = require('./helpers/SerializationHelper.test.js');
// handshake message
let FinishedMessageTest = require('./messages/handshake/FinishedMessage.test.js');
let HelloVerifyRequestMessageTest = require('./messages/handshake/HelloVerifyRequestMessage.test.js');
let PskClientKeyExchangeMessageTest = require('./messages/handshake/PskClientKeyExchangeMessage.test.js');
let ServerHelloDoneMessageTest = require('./messages/handshake/ServerHelloDoneMessage.test.js');

// helpers
test('>> Testing /helpers/SerializationHelper.js', SerializationHelperTest.testAll);
// handshake message
test('>> Testing /messages/handshake/FinishedMessage.js', FinishedMessageTest.testAll);
test('>> Testing /messages/handshake/HelloVerifyRequestMessage.js', HelloVerifyRequestMessageTest.testAll);
test('>> Testing /messages/handshake/PskClientKeyExchangeMessage.js', PskClientKeyExchangeMessageTest.testAll);
test('>> Testing /messages/handshake/ServerHelloDoneMessage.js', ServerHelloDoneMessageTest.testAll);
