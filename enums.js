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
    return (typeof this.DtlsVersion.properties[dtlsVersion] !== "undefined");
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
    return (typeof this.CipherSuite.properties[cipherSuite] !== "undefined");
}
exports.isCipherSuiteNull = function() {
    return (this.CipherSuite === CipherSuite.TLS_NULL_WITH_NULL_NULL);
}

exports.CompressionMethod = Object.freeze({
    // NOTE: DTLS version numbers are represented as the ones-complement of the actual values (to easily distinguish DTLS from TLS)
    NULL: 0x00,
    properties: {
        0x00: {name: "NULL"},
    }
}); 
exports.isCompressionMethodValid = function(compressionMethod) {
    return (typeof this.CompressionMethod.properties[compressionMethod] !== "undefined");
}



/* DtlsRecord enums */

const MAX_DTLS_10_COOKIE_LENGTH = 32; // DTLS 1.0

exports.getMaximumCookieLength = function(version) {
    if (!this.isDtlsVersionValid(version)) {
        throw new RangeError();
    }
    switch (version) {
        case this.DtlsVersion.DTLS_1_0:
            return MAX_DTLS_10_COOKIE_LENGTH;
        default:
            // NOTE: this should never be reached, as the isDtlsVersionValid(...) call should have eliminated any unknown versions
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
    return (typeof this.ChangeCipherSpecType.properties[type] !== "undefined");
}



/* DtlsHandshakeMessage enums */

exports.MessageType = Object.freeze({
    // HelloRequest: 0x00,
    ClientHello: 0x01,
    ServerHello: 0x02,
    HelloVerifyRequest: 0x03,
    // Certificate: 0x0b,
    // ServerKeyExchange: 0x0c,
    // CertificateRequest: 0x0d,
    ServerHelloDone: 0x0e,
    // CertificateVerify: 0x0f,
    ClientKeyExchange: 0x10,
    Finished: 0x14,
    properties: {
        // 0x00: {name: "HelloRequest"},
        0x01: {name: "ClientHello"},
        0x02: {name: "ServerHello"},
        0x03: {name: "HelloVerifyRequest"},
        // 0x0b: {name: "Certificate"},
        // 0x0c: {name: "ServerKeyExchange"},
        // 0x0d: {name: "CertificateRequest"},
        0x0e: {name: "ServerHelloDone"},
        // 0x0f: {name: "CertificateVerify"},
        0x10: {name: "ClientKeyExchange"},
        0x14: {name: "Finished"},
    }
});
exports.isMessageTypeValid = function(messageType) {
    return (typeof this.MessageType.properties[messageType] !== "undefined");
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
    return (typeof this.AlertLevel.properties[alertLevel] !== "undefined");
}

// NOTE: as we add/uncomment more AlertDescription members, we must also update the isAlertDescriptionAlwaysFatal function below (to be sync'd)
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
    // ExportRestrictionRESERVED: 60,
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
        // 60: {name: "ExportRestrictionRESERVED"},
        // 70: {name: "ProtocolVersion"},
        // 71: {name: "InsufficientSecurity"},
        // 80: {name: "InternalError"},
        // 90: {name: "UserCanceled"},
        // 100: {name: "NoRenegotiation"},
    }
});
exports.isAlertDescriptionValid = function(alertDescription) {
    return (typeof this.AlertDescription.properties[alertDescription] !== "undefined");
}
// NOTE: this extra helper function helps our session object determine when an alert description should be considered fatal, regardless of the supplied "level".
exports.isAlertDescriptionAlwaysFatal = function(alertDescription) {
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
