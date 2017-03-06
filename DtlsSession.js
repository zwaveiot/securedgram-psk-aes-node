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

// cryptoutils
let CryptoUtils = require("./CryptoUtils.js");
// securityParameters
let SecurityParameters = require('./SecurityParameters.js');
// messages
let ClientHelloMessage = require('./messages/handshake/ClientHelloMessage.js');
let HelloVerifyRequestMessage = require('./messages/handshake/HelloVerifyRequestMessage.js');
let ServerHelloMessage = require('./messages/handshake/ServerHelloMessage.js');
let ServerHelloDoneMessage = require('./messages/handshake/ServerHelloDoneMessage.js');
let PskClientKeyExchangeMessage = require('./messages/handshake/PskClientKeyExchangeMessage.js');
let FinishedMessage = require('./messages/handshake/FinishedMessage.js');
//
let DtlsAlertMessage = require('./messages/DtlsAlertMessage.js');
let DtlsApplicationDataMessage = require('./messages/DtlsApplicationDataMessage.js');
let DtlsChangeCipherSpecMessage = require('./messages/DtlsChangeCipherSpecMessage.js');
let DtlsHandshakeMessage = require('./messages/DtlsHandshakeMessage.js');
// records
let DtlsRecord = require('./DtlsRecord.js');
// enums
let enums = require('./enums.js');

// constantsh
// NOTE: we consider "UTC + random" to be one "random" code; the DtlsSession class is responsible for populating the first four bytes with a Utc value (with a random offset)
const CLIENT_RANDOM_SUFFIX_LENGTH = 28; 
const CLIENT_RANDOM_LENGTH = 32;
const DTLS_VERSION = enums.DtlsVersion.DTLS_1_0;
// supported cipher suites
let supportedCipherSuites = [
    // NOTE: we specify AES256 first so that the Z/IP gateway choosse the highest security by default
    enums.CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA,
    enums.CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA,
]; // supported compression methods
let supportedCompressionMethods = [
    enums.CompressionMethod.NULL,
];

exports.createDtlsSession = function(socket, dtlsSocket, messageListener) {
    let result = new DtlsSession(socket, dtlsSocket);
    if (messageListener !== undefined) {
        result.messageListener = messageListener;
    }
    return result;
};

function DtlsSession(socket, dtlsSocket) {
    // we keep a reverse reference to our socket so it can forward event notifications back to its owner
    this.dtlsSocket = dtlsSocket;
    // event listeners
    this.connectListener = null;
    this.disconnectListener = null;
    this.messageListener = null;
    // our dstIpAddress and dstPort values (stored so that the DtlsSocket can determine if an outgoing or incoming message matches an existing DtlsSession)
    this.dstIpAddress = null;
    this.dstPort = 0;
    // master secret and other security values we cannot erase from memory
    this.pskIdentity = null;
    this.pskPassword = null;
    // session id and datagram socket
    this.sessionId = null; // will be a buffer if there is an actual sessionId specified by the server
    this.socket = socket; // save our dgram socket
    // sequence numbers
    /* NOTE: epoch has a range of 0 to 2 to the power of 16; sequenceNumber has a range of 0 to 2 to the power of 48
     *       sequenceNumbers cannot roll over, so a ChangeCipherSpec message must be used to increase the epoch when a sequenceNumber would exceed 2 to the power of 48.
     *       epochs cannot roll over, so the session must be renegotiated when an epoch would exceed 2 to the power of 16. */
    this.nextOutgoingEpoch = 0;
    this.nextOutgoingSequenceNumber = 0;
    this.nextIncomingEpoch = 0;
    this.nextIncomingSequenceNumber = 0;
    // connection states
    // NOTE: all records are processed under the current read and write states (not the pending read and write states)
    //       [the pending read/write state becomes the current read/write when we receive or send a ChangeCipherSpec message, respectively--and the pending state becomes null]
    this.currentReadState = new DtlsConnectionState(enums.BulkEncryptionAlgorithm.NULL, enums.CompressionMethod.NULL, enums.MacAlgorithm.NULL);
    this.currentWriteState = new DtlsConnectionState(enums.BulkEncryptionAlgorithm.NULL, enums.CompressionMethod.NULL, enums.MacAlgorithm.NULL);
    // this.pendingReadState = null;
    // this.pendingWriteState = null;
    // security parameters
    this.securityParameters = SecurityParameters.create();
    // handshake message sequence (reset to zero when new handshake begins)
    this.handshakeMessageSequence = null;
    // allHandshakeMessagesAsBuffer is used to calculate the FINISHED message's payload
    this.allHandshakeMessagesAsBuffer = null;
    // session state
    this.sessionState = enums.SessionState.NotConnected;
    // message queue
    this.messageQueue = [];
}

function DtlsConnectionState(bulkEncryptionAlgorithm, compressionMethod, macAlgorithm) {
    this.bulkEncryptionAlgorithm = bulkEncryptionAlgorithm;
    this.compressionMethod = compressionMethod;
    this.macAlgorithm = macAlgorithm;
}

/* NOTE: the caller must provide an ipAddress to this function so that future outgoing and incoming packets can be matched to this session
 *       [due to limitations in IP headers, we cannot distinguish between hostnames, so all data sent to/from a single IP address must use the same pskIdentity and pskPassword--
 *        unless the user creates additional DtlsSocket(s) to handle the additional hostname(s) which would use different incoming ports. */
DtlsSession.prototype.connect = function(port, ipAddress, pskIdentity, pskPassword, connectListener, disconnectListener) {
    // verify that crypto is available; if not, return an error
    if (!CryptoUtils.verifyCrypto()) {
        console.log('CRITICAL ERROR: crypto not available.');
        return;
    }

    this.dstIpAddress = ipAddress;
    this.dstPort = port;
    this.connectListener = connectListener;
    this.disconnectListener = disconnectListener;

    this.pskIdentity = pskIdentity;
    this.pskPassword = pskPassword;

    // before we start negotiating our handshake, reset the allHandshakeMessagesAsBuffer and handshakeMessageSequence
    this.allHandshakeMessagesAsBuffer = Buffer.alloc(0);
    this.handshakeMessageSequence = 0;

    // step 1: send ClientHello Handshake message
    this.securityParameters.clientRandom = generateClientRandom();
    let cookie = null;
    let clientHelloMessage = ClientHelloMessage.create(DTLS_VERSION, this.securityParameters.clientRandom, this.sessionId, cookie, supportedCipherSuites, supportedCompressionMethods);
    let clientHelloMessageAsBuffer = clientHelloMessage.toBuffer();
    //
    let handshakeMessage = DtlsHandshakeMessage.createFromMessageBuffer(enums.MessageType.ClientHello, clientHelloMessageAsBuffer.length, this.handshakeMessageSequence, 0, clientHelloMessageAsBuffer.length, clientHelloMessageAsBuffer);
    let handshakeMessageAsBuffer = handshakeMessage.toBuffer();
    // increment the handshake message sequence
    this.handshakeMessageSequence += 1;
    // add the handshake message to our "finished" aggregate message source
    this.allHandshakeMessagesAsBuffer = Buffer.concat([this.allHandshakeMessagesAsBuffer, handshakeMessageAsBuffer]);
    //
    let dtlsRecord = DtlsRecord.createFromPlaintext(enums.ProtocolType.DtlsHandshakeProtocol, enums.DtlsVersion.DTLS_1_0, this.nextOutgoingEpoch, this.nextOutgoingSequenceNumber, handshakeMessageAsBuffer);
    let dtlsRecordAsBuffer = dtlsRecord.toEncryptedBuffer(this.currentWriteState.bulkEncryptionAlgorithm, this.securityParameters.clientWriteKey, this.currentWriteState.macAlgorithm, this.securityParameters.clientWriteMacSecret);
    //
    this.incrementNextOutgoingSequenceNumber();
    // update session state to "ClientHelloSent"
    this.sessionState = enums.SessionState.ClientHelloSent;
    this.socket.send(dtlsRecordAsBuffer, 0, dtlsRecordAsBuffer.length, port, ipAddress, null /* success/failure callback */);    
}

DtlsSession.prototype.sendApplicationData = function(data) {
    if (this.sessionState !== enums.SessionState.Connected) {
        this.messageQueue.push(data);
        return;
    }

    let dtlsApplicationDataMessage = DtlsApplicationDataMessage.create(data);
    let dtlsApplicationDataMessageAsBuffer = dtlsApplicationDataMessage.toBuffer();
    //
    let dtlsRecord = DtlsRecord.createFromPlaintext(enums.ProtocolType.DtlsApplicationDataProtocol, enums.DtlsVersion.DTLS_1_0, this.nextOutgoingEpoch, this.nextOutgoingSequenceNumber, dtlsApplicationDataMessageAsBuffer);
    let dtlsRecordAsBuffer = dtlsRecord.toEncryptedBuffer(this.currentWriteState.bulkEncryptionAlgorithm, this.securityParameters.clientWriteKey, this.currentWriteState.macAlgorithm, this.securityParameters.clientWriteMacSecret);
    //
    this.incrementNextOutgoingSequenceNumber();
    //
    this.socket.send(dtlsRecordAsBuffer, 0, dtlsRecordAsBuffer.length, this.dstPort, this.dstIpAddress, null /* success/failure callback */);    
}

DtlsSession.prototype.incrementNextOutgoingSequenceNumber = function() {
    this.nextOutgoingSequenceNumber++;
}

DtlsSession.prototype.incrementNextOutgoingEpoch = function() {
    this.nextOutgoingEpoch++;
    this.nextOutgoingSequenceNumber = 0;
}

function generateClientRandom() {
    if (!CryptoUtils.verifyCrypto()) return null;

    // create a buffer for the full random value
    let result = new Buffer(CLIENT_RANDOM_LENGTH);

    // generate 28 random bytes; we will pretend the "utc with random offset" before these bytes
    let randomBytes = CryptoUtils.crypto.randomBytes(CLIENT_RANDOM_SUFFIX_LENGTH);
    // generate utc with random offset
    let utcWithRandomOffset = calculateUtcWithRandomOffset();
    // populate the first four bytes of the result with the "utc with random offset" prefix value
    result.writeUInt32BE(utcWithRandomOffset, 0);
    // copy the random bytes (the suffix) to the result
    randomBytes.copy(result, 4, 0, randomBytes.length);
    
    // return the result
    return result;
}

function calculateUtcWithRandomOffset() {
    if (!CryptoUtils.verifyCrypto()) return null;

    // get the current time in seconds
    let result = Math.floor(Date.now() / 1000);
    // create a small (24-bit) random offset to avoid "server fingerprinting" 
    let randomOffset = CryptoUtils.crypto.randomBytes(3);
    let randomOffsetAsNumber = (randomOffset[0] << 16) | (randomOffset[1] << 8) | randomOffset[2];
    // split the randomOffset +/- an equal distance from zero (so that the offset could be either positive or negative)
    randomOffsetAsNumber -= (1 << 23);
    // add the random offset to the (utc) result
    result += randomOffsetAsNumber;
    // return the (utc with random offset) result
    return result;
}

DtlsSession.prototype.onSocketMessage = function(msg, rinfo) {
    let messageOffset = 0;
    // retrieve all messages contained within the datagram
    while (messageOffset < msg.length) {
        let dtlsRecord_FromBufferResult = DtlsRecord.fromEncryptedBuffer(msg, messageOffset, this.currentReadState.bulkEncryptionAlgorithm, this.securityParameters.serverWriteKey, this.currentReadState.macAlgorithm, this.securityParameters.serverWriteMacSecret);
        let dtlsRecord = dtlsRecord_FromBufferResult.record;
        if (dtlsRecord == null) {
            // discard the entire datagram
            break;
        }
        messageOffset += dtlsRecord_FromBufferResult.bytesConsumed;
        switch (dtlsRecord.protocolType) {
            case enums.ProtocolType.DtlsHandshakeProtocol: 
                {
                    let dtlsHandshakeMessage_FromBufferResult = DtlsHandshakeMessage.fromBuffer(dtlsRecord.fragment);
                    let dtlsHandshakeMessage = dtlsHandshakeMessage_FromBufferResult.record;
                    // determine the specific handshake protocol message
                    switch (dtlsHandshakeMessage.messageType) {
                        case enums.MessageType.HelloVerifyRequest:
                            {
                                let helloVerifyRequestMessage_FromBufferResult = HelloVerifyRequestMessage.fromBuffer(dtlsHandshakeMessage.message);
                                let helloVerifyRequestMessage = helloVerifyRequestMessage_FromBufferResult.message;
                                // first: if we receive a helloVerifyRequestMessage, we should reset our "allHandshakeMessagesAsBuffer"
                                this.allHandshakeMessagesAsBuffer = Buffer.alloc(0);
                                // extract the cookie from the HelloVerifyRequest message
                                let cookie = helloVerifyRequestMessage.cookie;

                                // resend the helloVerifyRequest message, including the verification cookie.
                                this.handshakeMessageSequence = 0;

                                // send ClientHello Handshake message
                                let clientHelloMessage = ClientHelloMessage.create(DTLS_VERSION, this.securityParameters.clientRandom, this.sessionId, cookie, supportedCipherSuites, supportedCompressionMethods);
                                let clientHelloMessageAsBuffer = clientHelloMessage.toBuffer();
                                //
                                let handshakeMessage = DtlsHandshakeMessage.createFromMessageBuffer(enums.MessageType.ClientHello, clientHelloMessageAsBuffer.length, this.handshakeMessageSequence, 0, clientHelloMessageAsBuffer.length, clientHelloMessageAsBuffer);
                                let handshakeMessageAsBuffer = handshakeMessage.toBuffer();
                                // increment the handshake message sequence
                                this.handshakeMessageSequence += 1;
                                // add the handshake message to our "finished" aggregate message source
                                this.allHandshakeMessagesAsBuffer = Buffer.concat([this.allHandshakeMessagesAsBuffer, handshakeMessageAsBuffer]);
                                //
                                let dtlsRecord = DtlsRecord.createFromPlaintext(enums.ProtocolType.DtlsHandshakeProtocol, enums.DtlsVersion.DTLS_1_0, this.nextOutgoingEpoch, this.nextOutgoingSequenceNumber, handshakeMessageAsBuffer);
                                let dtlsRecordAsBuffer = dtlsRecord.toEncryptedBuffer(this.currentWriteState.bulkEncryptionAlgorithm, this.securityParameters.clientWriteKey, this.currentWriteState.macAlgorithm, this.securityParameters.clientWriteMacSecret);
                                //
                                this.incrementNextOutgoingSequenceNumber();
                                // update session state to "ClientHelloSent"
                                this.sessionState = enums.SessionState.ClientHelloSent;
                                this.socket.send(dtlsRecordAsBuffer, 0, dtlsRecordAsBuffer.length, this.dstPort, this.dstIpAddress, null /* success/failure callback */);    
                            }
                            break;
                        case enums.MessageType.ServerHello:
                            {
                                let serverHelloMessage_FromBufferResult = ServerHelloMessage.fromBuffer(dtlsHandshakeMessage.message);
                                let serverHelloMessage = serverHelloMessage_FromBufferResult.message;
                                // add the handshake message to our "finished" aggregate message source
                                this.allHandshakeMessagesAsBuffer = Buffer.concat([this.allHandshakeMessagesAsBuffer, dtlsHandshakeMessage.toBuffer()]);
                                // store the received ServerRandom value
                                this.securityParameters.serverRandom = serverHelloMessage.random;

                                // store the server-selected encryption algorithm (from our supported algorithms)
                                switch (serverHelloMessage.cipherSuite) {
                                    case enums.CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
                                        this.securityParameters.bulkEncryptionAlgorithm = enums.BulkEncryptionAlgorithm.AES_128_CBC;
                                        this.securityParameters.macAlgorithm = enums.MacAlgorithm.SHA1;
                                        break;
                                    case enums.CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
                                        this.securityParameters.bulkEncryptionAlgorithm = enums.BulkEncryptionAlgorithm.AES_256_CBC;
                                        this.securityParameters.macAlgorithm = enums.MacAlgorithm.SHA1;
                                        break;
                                    default:
                                        return; // for now, our default behavior will be to just abort the handshake process
                                }

                                // store the server-selected compression method (from our supported algorithms)
                                switch (serverHelloMessage.compressionMethod) {
                                    case enums.CompressionMethod.NULL:
                                        this.securityParameters.compressionMethod = enums.CompressionMethod.NULL;
                                        break;
                                    default:
                                        return; // for now, our default behavior will be to just abort the handshake process                                    
                                }
                            }
                            break;
                        case enums.MessageType.ServerHelloDone:
                            {
                                if (!CryptoUtils.verifyCrypto()) return null;

                                let serverHelloDoneMessage_FromBufferResult = ServerHelloDoneMessage.fromBuffer(dtlsHandshakeMessage.message);
                                let serverHelloDoneMessage = serverHelloDoneMessage_FromBufferResult.message;
                                // add the handshake message to our "finished" aggregate message source
                                this.allHandshakeMessagesAsBuffer = Buffer.concat([this.allHandshakeMessagesAsBuffer, dtlsHandshakeMessage.toBuffer()]);

                                // upon receiving ServerHelloDone, we must send our second flight (ClientKeyExchange, ChangeCipherSpec and Finished messages)

                                // send our ClientKeyExchange message
                                let pskClientKeyExchangeMessage = PskClientKeyExchangeMessage.create(this.pskIdentity);
                                let pskClientKeyExchangeMessageAsBuffer = pskClientKeyExchangeMessage.toBuffer();
                                //
                                let handshakeMessage = DtlsHandshakeMessage.createFromMessageBuffer(enums.MessageType.ClientKeyExchange, pskClientKeyExchangeMessageAsBuffer.length, this.handshakeMessageSequence, 0, pskClientKeyExchangeMessageAsBuffer.length, pskClientKeyExchangeMessageAsBuffer);
                                let handshakeMessageAsBuffer = handshakeMessage.toBuffer();
                                // increment the handshake message sequence
                                this.handshakeMessageSequence += 1;
                                // add the handshake message to our "finished" aggregate message source
                                this.allHandshakeMessagesAsBuffer = Buffer.concat([this.allHandshakeMessagesAsBuffer, handshakeMessageAsBuffer]);
                                //
                                let dtlsRecord = DtlsRecord.createFromPlaintext(enums.ProtocolType.DtlsHandshakeProtocol, enums.DtlsVersion.DTLS_1_0, this.nextOutgoingEpoch, this.nextOutgoingSequenceNumber, handshakeMessageAsBuffer);
                                let dtlsRecordAsBuffer = dtlsRecord.toEncryptedBuffer(this.currentWriteState.bulkEncryptionAlgorithm, this.securityParameters.clientWriteKey, this.currentWriteState.macAlgorithm, this.securityParameters.clientWriteMacSecret);
                                //
                                this.incrementNextOutgoingSequenceNumber();
                                this.socket.send(dtlsRecordAsBuffer, 0, dtlsRecordAsBuffer.length, this.dstPort, this.dstIpAddress, null /* success/failure callback */);    

                                // before sending our ChangeCipherSpec message, calculate our security parameters
                                //
                                // calculate our (temporary) premaster secret
                                let premasterSecret = CryptoUtils.createPremasterSecret_FromPresharedKey(this.pskPassword);
                                // derive our master secret from our premasterSecret and our random values
                                this.securityParameters.masterSecret = CryptoUtils.PRF(premasterSecret, "master secret", Buffer.concat([this.securityParameters.clientRandom, this.securityParameters.serverRandom]), 48)
                                // as a standard security precaution, write over the premaster secret, and then dispose of it [NOTE: as we are garbage collected, this may not add much protection in some cases.]
                                let wipeRandomBytes = CryptoUtils.crypto.randomBytes(premasterSecret.length);
                                for (let iWipeByte = 0; iWipeByte < premasterSecret.length; iWipeByte++) {
                                    premasterSecret[iWipeByte] = wipeRandomBytes[iWipeByte];
                                }
                                premasterSecret = null;
                                //
                                // generate our key block
                                let clientWriteMacSecretLength = enums.getMacAlgorithmHashSize(this.securityParameters.macAlgorithm);
                                let serverWriteMacSecretLength = enums.getMacAlgorithmHashSize(this.securityParameters.macAlgorithm);
                                let clientWriteKeyLength = enums.getBulkAlgorithmKeySize(this.securityParameters.bulkEncryptionAlgorithm);
                                let serverWriteKeyLength = enums.getBulkAlgorithmKeySize(this.securityParameters.bulkEncryptionAlgorithm);
                                let keyBlockRequiredLength = clientWriteMacSecretLength + serverWriteMacSecretLength + clientWriteKeyLength + serverWriteKeyLength;
                                //
                                let keyBlockAsBuffer = CryptoUtils.PRF(this.securityParameters.masterSecret, "key expansion", Buffer.concat([this.securityParameters.serverRandom, this.securityParameters.clientRandom]), keyBlockRequiredLength);
                                // extract the MAC secrets and encryption keys from the keyBlock
                                let keyBlockOffset = 0;
                                this.securityParameters.clientWriteMacSecret = Buffer.alloc(clientWriteMacSecretLength);
                                keyBlockAsBuffer.copy(this.securityParameters.clientWriteMacSecret, 0, keyBlockOffset, keyBlockOffset + clientWriteMacSecretLength);
                                keyBlockOffset += clientWriteMacSecretLength;
                                //
                                this.securityParameters.serverWriteMacSecret = Buffer.alloc(serverWriteMacSecretLength);
                                keyBlockAsBuffer.copy(this.securityParameters.serverWriteMacSecret, 0, keyBlockOffset, keyBlockOffset + serverWriteMacSecretLength);
                                keyBlockOffset += serverWriteMacSecretLength;
                                //
                                this.securityParameters.clientWriteKey = Buffer.alloc(clientWriteKeyLength);
                                keyBlockAsBuffer.copy(this.securityParameters.clientWriteKey, 0, keyBlockOffset, keyBlockOffset + clientWriteKeyLength);
                                keyBlockOffset += clientWriteKeyLength;
                                //
                                this.securityParameters.serverWriteKey = Buffer.alloc(serverWriteKeyLength);
                                keyBlockAsBuffer.copy(this.securityParameters.serverWriteKey, 0, keyBlockOffset, keyBlockOffset + serverWriteKeyLength);
                                keyBlockOffset += serverWriteKeyLength;

                                // send our ChangeCipherSpec message
                                let changeCipherSpecMessage = DtlsChangeCipherSpecMessage.create(enums.ChangeCipherSpecType.One);
                                let changeCipherSpecMessageAsBuffer = changeCipherSpecMessage.toBuffer();
                                //
                                dtlsRecord = DtlsRecord.createFromPlaintext(enums.ProtocolType.DtlsChangeCipherSpecProtocol, enums.DtlsVersion.DTLS_1_0, this.nextOutgoingEpoch, this.nextOutgoingSequenceNumber, changeCipherSpecMessageAsBuffer);
                                dtlsRecordAsBuffer = dtlsRecord.toEncryptedBuffer(this.currentWriteState.bulkEncryptionAlgorithm, this.securityParameters.clientWriteKey, this.currentWriteState.macAlgorithm, this.securityParameters.clientWriteMacSecret);
                                //
                                this.incrementNextOutgoingEpoch(); // increase our epoch
                                this.socket.send(dtlsRecordAsBuffer, 0, dtlsRecordAsBuffer.length, this.dstPort, this.dstIpAddress, null /* success/failure callback */);
                                // immediately update our current write cipher
                                this.currentWriteState = new DtlsConnectionState(this.securityParameters.bulkEncryptionAlgorithm, this.securityParameters.compressionMethod, this.securityParameters.macAlgorithm);

                                // calculate the "verify" data for our Finished message
                                let clientVerifyDataFirstHalf = CryptoUtils.crypto.createHash('md5').update(this.allHandshakeMessagesAsBuffer).digest();
                                let clientVerifyDataSecondHalf = CryptoUtils.crypto.createHash('sha1').update(this.allHandshakeMessagesAsBuffer).digest();
                                let clientVerifyData = CryptoUtils.PRF(this.securityParameters.masterSecret, "client finished", Buffer.concat([clientVerifyDataFirstHalf, clientVerifyDataSecondHalf]), 12);

                                // send our Finished message
                                let finishedMessage = FinishedMessage.create(clientVerifyData);
                                let finishedMessageAsBuffer = finishedMessage.toBuffer();
                                //
                                handshakeMessage = DtlsHandshakeMessage.createFromMessageBuffer(enums.MessageType.Finished, finishedMessageAsBuffer.length, this.handshakeMessageSequence, 0, finishedMessageAsBuffer.length, finishedMessageAsBuffer);
                                handshakeMessageAsBuffer = handshakeMessage.toBuffer();
                                // increment the handshake message sequence
                                this.handshakeMessageSequence += 1;
                                // add the handshake message to our "finished" aggregate message source
                                this.allHandshakeMessagesAsBuffer = Buffer.concat([this.allHandshakeMessagesAsBuffer, handshakeMessageAsBuffer]);
                                //
                                dtlsRecord = DtlsRecord.createFromPlaintext(enums.ProtocolType.DtlsHandshakeProtocol, enums.DtlsVersion.DTLS_1_0, this.nextOutgoingEpoch, this.nextOutgoingSequenceNumber, handshakeMessageAsBuffer);
                                dtlsRecordAsBuffer = dtlsRecord.toEncryptedBuffer(this.currentWriteState.bulkEncryptionAlgorithm, this.securityParameters.clientWriteKey, this.currentWriteState.macAlgorithm, this.securityParameters.clientWriteMacSecret);
                                //
                                this.incrementNextOutgoingSequenceNumber();
                                //
                                // update session state to "FinishedSent"
                                this.sessionState = enums.SessionState.FinishedSent;
                                //
                                this.socket.send(dtlsRecordAsBuffer, 0, dtlsRecordAsBuffer.length, this.dstPort, this.dstIpAddress, null /* success/failure callback */);    
                            }
                            break;
                        case enums.MessageType.Finished:
                            {
                                let finishedMessage_FromBufferResult = FinishedMessage.fromBuffer(dtlsHandshakeMessage.message);
                                let finishedMessage = finishedMessage_FromBufferResult.message;

                                // calculate the "verify" data for our Finished message
                                let serverVerifyDataFirstHalf = CryptoUtils.crypto.createHash('md5').update(this.allHandshakeMessagesAsBuffer).digest();
                                let serverVerifyDataSecondHalf = CryptoUtils.crypto.createHash('sha1').update(this.allHandshakeMessagesAsBuffer).digest();
                                let serverVerifyData = CryptoUtils.PRF(this.securityParameters.masterSecret, "server finished", Buffer.concat([serverVerifyDataFirstHalf, serverVerifyDataSecondHalf]), 12);

                                // verify verifyData   
                                if (Buffer.compare(serverVerifyData, finishedMessage.verifyData) !== 0) {
                                    return null;
                                } else {
                                    // update session state to "Connected"
                                    this.sessionState = enums.SessionState.Connected;
                                    if (this.connectListener) {
                                        this.connectListener(this);
                                    }

                                    while (this.messageQueue.length > 0) {
                                        let data = this.messageQueue.pop();
                                        this.sendApplicationData(data);
                                    }
                                }
                            }
                            break;
                        default:
                            break;
                    }
                }
                break;
            case enums.ProtocolType.DtlsChangeCipherSpecProtocol: 
                {
                    let dtlsChangeCipherSpecMessage_FromBufferResult = DtlsChangeCipherSpecMessage.fromBuffer(dtlsRecord.fragment);
                    let dtlsChangeCipherSpecMessage = dtlsChangeCipherSpecMessage_FromBufferResult.record;

                    // verify the incoming DtlsChangeCipherSpecMessage
                    if (dtlsChangeCipherSpecMessage.type !== enums.ChangeCipherSpecType.One) {
                        return null;
                    }

                    // immediately update our current read cipher
                    this.currentReadState = new DtlsConnectionState(this.securityParameters.bulkEncryptionAlgorithm, this.securityParameters.compressionMethod, this.securityParameters.macAlgorithm);
                }
                break;
            case enums.ProtocolType.DtlsAlertProtocol:
                {
                    let dtlsAlertMessage_FromBufferResult = DtlsAlertMessage.fromBuffer(dtlsRecord.fragment);
                    let dtlsAlertMessage = dtlsAlertMessage_FromBufferResult.record;

                    switch (dtlsAlertMessage.description) {
                        case enums.AlertDescription.CloseNotify:
                            if (this.disconnectListener) {
                                this.disconnectListener(this.dtlsSocket, this);
                            }
                            break;
                        // case enums.AlertDescription.BadRecordMac:
                        //     break;
                        default:
                            break;
                    }
                }
                break;
            case enums.ProtocolType.DtlsApplicationDataProtocol:
                {
                    let dtlsApplicationDataMessage_FromBufferResult = DtlsApplicationDataMessage.fromBuffer(dtlsRecord.fragment);
                    let dtlsApplicationDataMessage = dtlsApplicationDataMessage_FromBufferResult.record;

                    // raise an event with the incoming message
                    if (this.messageListener) {
                        this.messageListener(this.dtlsSocket, this, dtlsApplicationDataMessage.data);
                    }
                }
                break;
            default:
                // ignore any unknown protocol types
                break;
        }
    }

}
