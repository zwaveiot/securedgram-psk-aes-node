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

/* Record layout:
 *      00: ProtocolType
 *      01: Version_Major (MSB)
 *      02: Version_Minor (LSB)
 *      03: Epoch MSB
 *      04: Epoch LSB
 *      05: Sequence Number MSB
 *      06: Sequence Number (continued)
 *      07: Sequence Number (continued)
 *      08: Sequence Number (continued)
 *      09: Sequence Number (continued)
 *      10: Sequence Number LSB
 *      11: Length MSB
 *      12: Length LSB
 *     13+: SslCiphertext Fragment
 */

// cryptoutils
let CryptoUtils = require("./CryptoUtils.js");
// enums
let enums = require('./enums.js');

// constants
const HEADER_LENGTH = 13;
//
const MAX_PLAINTEXT_FRAGMENT_LENGTH = 16384;
const MAIN_COMPRESSEDTEXT_FRAGMENT_LENGTH = MAX_PLAINTEXT_FRAGMENT_LENGTH + 1024;
const MAIN_CIPHERTEXT_FRAGMENT_LENGTH = MAIN_COMPRESSEDTEXT_FRAGMENT_LENGTH + 1024;
//
const MAX_EPOCH = (1 << 16) - 1;
const MAX_SEQUENCE_NUMBER = (1 << 48) - 1;

function DtlsRecord() {
    this.protocolType = null;
    this.dtlsVersion = null;
    this.epoch = null;
    this.sequenceNumber = null;
    this.fragment = null;
}

exports.createFromPlaintext = function(type, dtlsVersion, epoch, sequenceNumber, fragment) {
    // validate inputs
    //
    // type
    if (!enums.isProtocolTypeValid(type)) {
        throw new RangeError();
    }
    // dtlsVersion
    if (!enums.isDtlsVersionValid(dtlsVersion)) {
        throw new RangeError();
    }
    // epoch    
    // note: all positive integers up to (2^16)-1 are valid for epoch
    if (typeof epoch !== "number") {
        throw new TypeError();
    } else if ((epoch < 0) || (epoch > Math.pow(2, 16) - 1) || (Math.floor(epoch) != epoch)) {
        throw new RangeError();
    }
    // sequenceNumber
    // note: all positive integers up to (2^48)-1 are valid for sequenceNumber
    if (typeof sequenceNumber !== "number") {
        throw new TypeError();
    } else if ((sequenceNumber < 0) || (sequenceNumber > Math.pow(2, 48) - 1) || (Math.floor(sequenceNumber) != sequenceNumber)) {
        throw new RangeError();
    }
    // fragment
    if (Object.prototype.toString.call(fragment) != "[object Uint8Array]") {
        throw new TypeError();
    } else if (fragment.length > MAX_PLAINTEXT_FRAGMENT_LENGTH) {
        throw new RangeError();
    }

    // create and initialize the new DtlsRecord object
    let result = new DtlsRecord();
    result.protocolType = type;
    result.dtlsVersion = dtlsVersion;
    result.epoch = epoch;
    result.sequenceNumber = sequenceNumber;
    result.fragment = fragment;

    // return the new Dtls record object
    return result;
}

// NOTE: this function returns null if a complete record could not be parsed (and does not validate any data in the returned record)
// NOTE: offset is optional (default: 0)
exports.fromEncryptedBuffer = function(buffer, offset, bulkEncryptionAlgorithm, blockEncryptionKey, macAlgorithm, macSecret) {
    // use currentOffset to track the current offset while reading from the buffer    
    let initialOffset;
    let currentOffset;

    // validate inputs
    //
    // offset
    if (typeof offset === "undefined") {
        initialOffset = 0;
    } else if (typeof offset !== "number") {
        // if the offset is provided, but is not a number, then return an error
        throw new TypeError();        
    } else if (offset >= buffer.length) {
        throw new RangeError();
    } else {
        initialOffset = offset;    
    }
    currentOffset = initialOffset;
    // buffer
    if (typeof buffer === "undefined") {
        throw new TypeError();
    } else if (buffer  === null) {
        // null buffer is NOT acceptable
    } else if (Object.prototype.toString.call(buffer) != "[object Uint8Array]") {
        throw new TypeError();
    } else if (buffer.length - currentOffset < HEADER_LENGTH) {
        // buffer is not long enough for a full record; return null.
        return null;
    }
    
    // create the new DtlsRecord object
    let result = new DtlsRecord();

    // if we are expecting an encrypted ciphertext (i.e. not NULL encryption), create a RandomIVLength now
    let randomIVLength = 0;
    if (bulkEncryptionAlgorithm !== enums.BulkEncryptionAlgorithm.NULL) {
        randomIVLength = enums.getBulkAlgorithmBlockSize(bulkEncryptionAlgorithm);
    }

    // parse buffer
    //
    // type (octet 0)
    result.protocolType = buffer[currentOffset];
    currentOffset += 1;
    // dtlsVersion (octets 1-2)
    result.dtlsVersion = buffer.readUInt16BE(currentOffset);
    currentOffset += 2;
    // epoch (octets 3-4)
    result.epoch = buffer.readUInt16BE(currentOffset);
    currentOffset += 2;
    // sequenceNumber (octets 5-10)
    result.sequenceNumber = buffer.readUIntBE(currentOffset, 6);
    currentOffset += 6;
    // length (octets 11-12)
    let ciphertextLength = buffer.readUInt16BE(currentOffset);
    currentOffset += 2;
    // verify that the buffer length is long enough to fit the sslCiphertext
    if (buffer.length - currentOffset < ciphertextLength) {
        // if the buffer is not big enough, return null
        return null;
    }
    // randomIV
    let randomIV = null;
    if (randomIVLength < ciphertextLength) {
        randomIV = Buffer.alloc(randomIVLength);
        buffer.copy(randomIV, 0, currentOffset, currentOffset + randomIVLength);
        currentOffset += randomIVLength;
        // subtract the randomIVLength from the ciphertextLength (so that we do not try to include the randomIV in the ciphertext)
        ciphertextLength -= randomIVLength;
    } else {
        // invalid randomIVLength; assume an invalid packet
        randomIVLength = 0;
        return null;
    }
    // ciphertext
    let ciphertext = Buffer.alloc(ciphertextLength);
    buffer.copy(ciphertext, 0, currentOffset, currentOffset + ciphertextLength);
    currentOffset += ciphertextLength;

    // decrypt the ciphertext
    let compressedtext;
    if (bulkEncryptionAlgorithm === enums.BulkEncryptionAlgorithm.NULL || randomIV === null || randomIV.length === 0) {
        compressedtext = ciphertext;
    } else {
        if (!CryptoUtils.verifyCrypto()) return null;
                
        // decrypt with bulkEncryptionAlgorithm
        let bulkEncryptionAlgorithmAsString = enums.getBulkAlgorithmAsString(bulkEncryptionAlgorithm);
        let decryptionCrypto = CryptoUtils.crypto.createDecipheriv(bulkEncryptionAlgorithmAsString, blockEncryptionKey, randomIV);
        decryptionCrypto.setAutoPadding(false);
        let decryptData = decryptionCrypto.update(ciphertext);
        let finalBlock = decryptionCrypto.final();
        compressedtext = Buffer.concat([decryptData, finalBlock]);

        if (compressedtext.length === 0) return null;

        // verify padding
        // NOTE: to ensure constant-time operation, we check every byte of the compressedtext--including non-padding bytes.
        let paddingLength = compressedtext[compressedtext.length - 1];
        let paddingValueLength = 1;
        let paddingError = false;
        if (paddingLength + paddingValueLength > compressedtext.length) {
            paddingError = true;
        }
        if (paddingError) {
            for (let iPaddingByte = compressedtext.length - 1; iPaddingByte >= 0; iPaddingByte--) {
                if (compressedtext[iPaddingByte] != 0) {
                    // do nothing useful
                }
            }
        } else {
            for (let iPaddingByte = compressedtext.length - 1; iPaddingByte > compressedtext.length - paddingLength - paddingValueLength - 1; iPaddingByte--) {
                if (compressedtext[iPaddingByte] != paddingLength) {
                    paddingError = true;
                }
            }
            for (let iPaddingByte = compressedtext.length - paddingLength - paddingValueLength - 1; iPaddingByte >= 0; iPaddingByte--) {
                if (compressedtext[iPaddingByte] != 0) {
                    // do nothing useful
                }
            }            
        }

        // verify MAC hash regardless of if padding is valid or not
        let macHashError = false;
        // create a buffer which prepends the MAC info header
        let macHashLength = enums.getMacAlgorithmHashSize(macAlgorithm);
        let compressedtextWithoutMacOrPadding = compressedtext.slice(0, compressedtext.length - paddingLength - paddingValueLength - macHashLength);
        let macHash = compressedtext.slice(compressedtext.length - paddingLength - paddingValueLength - macHashLength, compressedtext.length - paddingLength - paddingValueLength)
        let bufferForMacCalculation = buildBufferForMacCalculation(result.epoch, result.sequenceNumber, result.protocolType, result.dtlsVersion, compressedtextWithoutMacOrPadding);
        // generate the MAC hash
        let macSecretAsBuffer = new Buffer(macSecret);
        let macHashVerify = CryptoUtils.crypto.createHmac('sha1', macSecretAsBuffer).update(bufferForMacCalculation).digest();
        // compare MAC hash to macHashVerify
        for (let iMacHash = 0; iMacHash < macHashLength; iMacHash++) {
            if (macHashVerify[iMacHash] !== macHash[iMacHash]) {
                macHashError = true;
            }
        }

        // remove mac and hash from compressedtext
        compressedtext = compressedtextWithoutMacOrPadding;

        if (macHashError) {
            return null;
        }
        if (paddingError) {
            return null;
        }
    }

    // decompress the compressedtext
    // NOTE: compression is not allowed by our implementation; simply copy the compressedtext reference to the result's fragment variable in case we add compression in the future
    result.fragment = Buffer.alloc(compressedtext.length)
    compressedtext.copy(result.fragment, 0, 0, result.fragment.length);

    // return the new DtlsRecord object
    return {record: result, bytesConsumed: currentOffset - initialOffset};
}

DtlsRecord.prototype.toEncryptedBuffer = function(bulkEncryptionAlgorithm, blockEncryptionKey, macAlgorithm, macSecret) {
    // compress the plaintext
    //
    // NOTE: compression is not allowed by our implementation; simply copy the fragment reference to the compressedtext variable in case we add compression in the future
    let compressedtext = this.fragment;

    // encrypt the compressedtext
    //
    let ciphertext;
    let randomIV = null;
    if (bulkEncryptionAlgorithm == enums.BulkEncryptionAlgorithm.NULL) {
        ciphertext = compressedtext;
    } else {
        if (!CryptoUtils.verifyCrypto()) return null;

        // generate an IV equal to the length of our cipher block
        let encryptionblockSize = enums.getBulkAlgorithmBlockSize(bulkEncryptionAlgorithm);
        randomIV = CryptoUtils.crypto.randomBytes(encryptionblockSize);
        //
        // create a buffer which prepends the MAC info header
        let bufferForMacCalculation = buildBufferForMacCalculation(this.epoch, this.sequenceNumber, this.protocolType, this.dtlsVersion, compressedtext);
        // generate the MAC hash
        let macSecretAsBuffer = new Buffer(macSecret);
        let macHash = CryptoUtils.crypto.createHmac('sha1', macSecretAsBuffer).update(bufferForMacCalculation).digest();
        //
        // for encryption, append the MAC hash to the fragment and then append padding to the closest blocksize
        let bufferForEncryption = buildBufferForEncryption(compressedtext, macHash, enums.getBulkAlgorithmBlockSize(bulkEncryptionAlgorithm));
        //
        // encrypt with bulkEncryptionAlgorithm
        let bulkEncryptionAlgorithmAsString = enums.getBulkAlgorithmAsString(bulkEncryptionAlgorithm);
        let encryptionCrypto = CryptoUtils.crypto.createCipheriv(bulkEncryptionAlgorithmAsString, blockEncryptionKey, randomIV);
        encryptionCrypto.setAutoPadding(false);
        let encryptData = encryptionCrypto.update(bufferForEncryption);
        let finalBlock = encryptionCrypto.final();
        ciphertext = Buffer.concat([encryptData, finalBlock]);
    }

    // create our buffer (which we will then populate)
    let randomIVLength = (randomIV !== null ? randomIV.length : 0);
    let ciphertextLength = ciphertext.length;
    let result = Buffer.alloc(HEADER_LENGTH + randomIVLength + ciphertextLength);
    // use offset to track the current offset while writing to the buffer    
    let offset = 0;

    // populate record header
    //
    // type (octet 0)
    result[offset] = this.protocolType;
    offset += 1;
    // dtlsVersion (octets 1-2)
    result.writeUInt16BE(this.dtlsVersion, offset);
    offset += 2;
    // epoch (octets 3-4)
    result.writeUInt16BE(this.epoch, offset);
    offset += 2;
    // sequenceNumber (octets 5-10)
    result.writeUIntBE(this.sequenceNumber, offset, 6);
    offset += 6;
    // length (octets 11-12)
    result.writeUInt16BE(ciphertextLength + randomIVLength, offset);
    offset += 2;
    // randomIV (octets 13+)
    if (randomIV !== null) {
        randomIV.copy(result, offset, 0, randomIVLength);
        offset += randomIVLength;
    }
    // ciphertext
    ciphertext.copy(result, offset, 0, ciphertextLength); 
    offset += ciphertextLength;

    // return the buffer (result)
    return result;
}

function buildBufferForMacCalculation(epoch, sequenceNumber, protocolType, dtlsVersion, fragment) {
    let fragmentLength = fragment.length;
    let result = Buffer.alloc(8 /* epoch + sequenceNumber */ + 5 /* protocolType + dtlsVersion */ + fragmentLength);

    let offset = 0;
    // epoch (octets 0-1)
    result.writeUInt16BE(epoch, offset);
    offset += 2;
    // sequenceNumber (octets 2-7)
    result.writeUIntBE(sequenceNumber, offset, 6);
    offset += 6;
    // protocolType (octet 8)
    result[offset] = protocolType;
    offset += 1;
    // dtlsVersion (octets 9-10)
    result.writeUInt16BE(dtlsVersion, offset);
    offset += 2
    // fragmentLength (octets 11-12)
    result.writeUInt16BE(fragmentLength, offset);
    offset += 2
    // fragmentBuffer
    fragment.copy(result, offset, 0, fragmentLength);
    offset += fragmentLength;

    return result;
}

function buildBufferForEncryption(fragment, macHash, paddingBlockSize) {
    let nonPaddedLength = fragment.length + macHash.length + 1 /* +1 is for the padding length byte which goes _after_ the padding */;
    let numBlocks = Math.ceil(nonPaddedLength / paddingBlockSize);
    let paddedLength = numBlocks * paddingBlockSize;
    let paddingLength = paddedLength - nonPaddedLength;
    //
    let offset = 0;
    let result = Buffer.alloc(paddedLength);
    //
    fragment.copy(result, offset, 0, fragment.length);
    offset += fragment.length;
    //
    macHash.copy(result, offset, 0, macHash.length);
    offset += macHash.length;
    // the padding
    result.fill(paddingLength, offset, offset + paddingLength);
    offset += paddingLength;
    // paddingLength
    result[offset] = paddingLength;
    //
    return result;
}

