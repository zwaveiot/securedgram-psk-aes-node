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

/* DtlsSession enums */

exports.DtlsVersion = Object.freeze({
    // NOTE: DTLS version numbers are represented as the ones-complement of the actual values (to easily distinguish DTLS from TLS)
    DTLS_1_0: 0xfeff,
    properties: {
        0xfeff: {name: "DTLS_1_0"},
    }
}); 
exports.isDtlsVersionValid = function(dtlsVersion) {
    return (this.DtlsVersion.properties[dtlsVersion] !== undefined);
}

exports.CipherSuite = Object.freeze({
    TLS_NULL_WITH_NULL_NULL: 0x0000,
    TLS_PSK_WITH_AES_128_CBC_SHA: 0x008C,
    TLS_PSK_WITH_AES_256_CBC_SHA: 0x008D,
    properties: {
        0x0000: {name: "TLS_NULL_WITH_NULL_NULL"},
        0x008C: {name: "TLS_PSK_WITH_AES_128_CBC_SHA"},
        0x008D: {name: "TLS_PSK_WITH_AES_256_CBC_SHA"},
    }
});
exports.isCipherSuiteValid = function(cipherSuite) {
    // NOTE: we do not reject the null cipher suite here
    return (this.CipherSuite.properties[cipherSuite] !== undefined);
}
exports.isCipherSuiteNull = function() {
    return (this.CipherSuite === CipherSuite.TLS_NULL_WITH_NULL_NULL);
}

// NOTE: the number values assigned to KeyExchangeAlgorithm members are for our own use, not from any specification
exports.KeyExchangeAlgorithm = Object.freeze({
    NULL: 0x00,
    PSK: 0x01,
    properties:
    {
        0x00: {name: "NULL"},
        0x01: {name: "PSK"},
    }
});
exports.isKeyExchangeAlgorithmValid = function(keyExchangeAlgorithm) {
    // NOTE: we do not reject the null key exchange algorithm here
    return (this.KeyExchangeAlgorithm.properties[keyExchangeAlgorithm] !== undefined);
}

// NOTE: the number values assigned to BulkEncryptionAlgorithm members are for our own use, not from any specification
exports.BulkEncryptionAlgorithm = Object.freeze({
    NULL: 0x00,
    AES_128_CBC: 0x01,
    AES_256_CBC: 0x02,
    properties:
    {
        0x00: {name: "NULL"},
        0x01: {name: "AES_128_CBC"},
        0x02: {name: "AES_256_CBC"},
    }
});
exports.isBulkEncryptionAlgorithmValid = function(bulkEncryptionAlgorithm) {
    // NOTE: we do not reject the null bulk encryption algorithm here
    return (this.BulkEncryptionAlgorithm.properties[bulkEncryptionAlgorithm] !== undefined);
}
exports.getBulkAlgorithmKeySize = function(bulkEncryptionAlgorithm) {
    switch (bulkEncryptionAlgorithm) {
        case this.BulkEncryptionAlgorithm.AES_128_CBC:
            return 16;
        case this.BulkEncryptionAlgorithm.AES_256_CBC:
            return 32;
        case this.BulkEncryptionAlgorithm.NULL:
            return 0;
        default:
            // invalid BulkEncryptionAlgorithm
            return null;
    }
}
exports.getBulkAlgorithmBlockSize = function(bulkEncryptionAlgorithm) {
    switch (bulkEncryptionAlgorithm) {
        case this.BulkEncryptionAlgorithm.AES_128_CBC:
        case this.BulkEncryptionAlgorithm.AES_256_CBC:
            return 16;
        case this.BulkEncryptionAlgorithm.NULL:
            return 1;
        default:
            // invalid BulkEncryptionAlgorithm
            return null;
    }
}
exports.getBulkAlgorithmAsString = function(bulkEncryptionAlgorithm) {
    switch (bulkEncryptionAlgorithm) {
        case this.BulkEncryptionAlgorithm.AES_128_CBC:
            return "aes-128-cbc";
        case this.BulkEncryptionAlgorithm.AES_256_CBC:
            return "aes-256-cbc";
        case this.BulkEncryptionAlgorithm.NULL:
            return "null";
        default:
            // invalid BulkEncryptionAlgorithm
            return null;
    }
}

// NOTE: the number values assigned to MacAlgorithm members are for our own use, not from any specification
exports.MacAlgorithm = Object.freeze({
    NULL: 0x00,
    SHA1: 0x01,
    properties:
    {
        0x00: {name: "NULL"},
        0x01: {name: "SHA1"},
    }
});
exports.isMacAlgorithmValid = function(macAlgorithm) {
    // NOTE: we do not reject the null mac algorithm here
    return (this.MacAlgorithm.properties[macAlgorithm] !== undefined);
}
exports.getMacAlgorithmHashSize = function(macAlgorithm) {
    switch (macAlgorithm) {
        case this.MacAlgorithm.SHA1:
            return 20;
        case this.MacAlgorithm.NULL:
            return 0;
        default:
            // invalid MacAlgorithm
            return null;
    }
}

exports.CompressionMethod = Object.freeze({
    // NOTE: DTLS version numbers are represented as the ones-complement of the actual values (to easily distinguish DTLS from TLS)
    NULL: 0x00,
    properties: {
        0x00: {name: "NULL"},
    }
}); 
exports.isCompressionMethodValid = function(compressionMethod) {
    return (this.CompressionMethod.properties[compressionMethod] !== undefined);
}

exports.SessionState = Object.freeze({
    NotConnected: 0,
    ClientHelloSent: 1,
    FinishedSent: 2,
    properties:
    {
        0: {name: "NotConnected"},
        1: {name: "ClientHelloSent"},
        2: {name: "FinishedSent"},
    }
});



/* DtlsRecord enums */

const MAX_DTLS_10_COOKIE_LENGTH = 32; // DTLS 1.0

exports.ProtocolType = Object.freeze({
    DtlsChangeCipherSpecProtocol: 0x14,
    DtlsAlertProtocol: 0x15,
    DtlsHandshakeProtocol: 0x16,
    DtlsApplicationDataProtocol: 0x17,
    properties: {
        0x14: {name: "DtlsChangeCipherSpecProtocol"},
        0x15: {name: "DtlsAlertProtocol"},
        0x16: {name: "DtlsHandshakeProtocol"},
        0x17: {name: "DtlsApplicationDataProtocol"}
    }
});
exports.isProtocolTypeValid = function(protocolType) {
    return (this.ProtocolType.properties[protocolType] !== undefined);
}

exports.getMaximumCookieLength = function(version) {
    if (!this.isVersionValid(version)) {
        throw new RangeError();
    }
    switch (version) {
        case this.VersionOption.DTLS_1_0:
            return MAX_DTLS_10_COOKIE_LENGTH;
        default:
            // NOTE: this should never be reached, as the isVersionValid(...) call should have eliminated any unknown versions
            throw new RangeError();
    }    
}



/* DtlsChangeCipherSpecMessage enums */
exports.ChangeCipherSpecType = Object.freeze({
    One: 0x01,
    properties: {
        0x01: {name: "One"},
    }
});
exports.isChangeCipherSpecTypeValid = function(type) {
    return (this.ChangeCipherSpecType.properties[type] !== undefined);
}



/* DtlsHandshakeRecord enums */

exports.MessageType = Object.freeze({
    ClientHello: 0x01,
    ServerHello: 0x02,
    HelloVerifyRequest: 0x03,
    ServerHelloDone: 0x0e,
    ClientKeyExchange: 0x10,
    Finished: 0x14,
    properties: {
        0x01: {name: "ClientHello"},
        0x02: {name: "ServerHello"},
        0x03: {name: "HelloVerifyRequest"},
        0x0e: {name: "ServerHelloDone"},
        0x10: {name: "ClientKeyExchange"},
        0x14: {name: "Finished"},
    }
});
exports.isMessageTypeValid = function(messageType) {
    return (this.MessageType.properties[messageType] !== undefined);
}



/* AlertProtocol enums */

exports.AlertLevel = Object.freeze({
    Warning: 1,
    Fatal: 2,
    properties: {
        1: {name: "Warning"},
        2: {name: "Fatal"},
    }
});
exports.isAlertLevelValid = function(alertLevel) {
    return (this.AlertLevel.properties[alertLevel] !== undefined);
}

exports.AlertDescription = Object.freeze({
    CloseNotify: 0,
    // UnexpectedMessage: 10,
    BadRecordMac: 20,
    // DecryptionFailed: 21,
    // RecordOverflow: 22,
    // DecompressionFailure: 30,
    // HandshakeFailure: 40,
    // NoCertificateRESERVED: 41,
    // BadCertificate: 42,
    // UnsupportedCertificate: 43,
    // CertificateRevoked: 44,
    // CertificateExpired: 45,
    // CertificateUnknown: 46,
    // IllegalParameter: 47,
    // UnknownCertificateAuthority: 48,
    // AccessDenied: 49,
    // DecodeError: 50,
    // DecryptError: 51,
    // ExportRestrictionRESERVED: 52,
    // ProtocolVersion: 70,
    // InsufficientSecurity: 71,
    // InternalError: 80,
    // UserCanceled: 90,
    // NoRenegotiation: 100,
    properties: {
        0: {name: "CloseNotify"},
        // 10: {name: "UnexpectedMessage"},
        20: {name: "BadRecordMac"},
        // 21: {name: "DecryptionFailed"},
        // 22: {name: "RecordOverflow"},
        // 30: {name: "DecompressionFailure"},
        // 40: {name: "HandshakeFailure"},
        // 41: {name: "NoCertificateRESERVED"},
        // 42: {name: "BadCertificate"},
        // 43: {name: "UnsupportedCertificate"},
        // 44: {name: "CertificateRevoked"},
        // 45: {name: "CertificateExpired"},
        // 46: {name: "CertificateUnknown"},
        // 47: {name: "IllegalParameter"},
        // 48: {name: "UnknownCertificateAuthority"},
        // 49: {name: "AccessDenied"},
        // 50: {name: "DecodeError"},
        // 51: {name: "DecryptError"},
        // 52: {name: "ExportRestrictionRESERVED"},
        // 70: {name: "ProtocolVersion"},
        // 71: {name: "InsufficientSecurity"},
        // 80: {name: "InternalError"},
        // 90: {name: "UserCanceled"},
        // 100: {name: "NoRenegotiation"},
    }
});
exports.isAlertDescriptionValid = function(alertDescription) {
    return (this.AlertDescription.properties[alertDescription] !== undefined);
}
exports.isAlertFatal = function(alertDescription) {
    switch (alertDescription) {
        // case this.AlertDescription.UnexpectedMessage:
        case this.AlertDescription.BadRecordMac:
        // case this.AlertDescription.DecryptionFailed:
        // case this.AlertDescription.RecordOverflow:
        // case this.AlertDescription.DecompressionFailure:
        // case this.AlertDescription.HandshakeFailure:
        // case this.AlertDescription.IllegalParameter:
        // case this.AlertDescription.UnknownCertificateAuthority:
        // case this.AlertDescription.AccessDenied:
        // case this.AlertDescription.DecodeError:
        // case this.AlertDescription.ProtocolVersion:
        // case this.AlertDescription.InsufficientSecurity:
        // case this.AlertDescription.InternalError:
            return true;
        default:
            return false;
    }
}
