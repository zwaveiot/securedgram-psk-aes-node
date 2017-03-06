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

// dgram
let dgram = require('dgram');
// DtlsSession
let DtlsSession = require('./DtlsSession.js');

exports.createDtlsSocket = function(type, callbackObject, callback) {
    let result = new DtlsSocket(type);
    result.callbackObject = callbackObject;
    result.messageListener = callback;
    return result;
};

function DtlsSocket(type) {
    this.dtlsSessions = null;
    this.messageListener = null;
    this.socket = null;
    this.socketType = type;
    
    // initialize our dtlsSessions to an empty set
    this.dtlsSessions = [];
    // create an underlying dgram socket (which will be shared by all DTLS sesssions)
    let thisObject = this;
    this.socket = dgram.createSocket(type, function(msg, rinfo) {DtlsSocket.prototype.onSocketMessage(thisObject, msg, rinfo)});
}

function isIpAddress(ipAddressFamily, ipAddress) {
    let ipv4RegExp = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    let ipv6RegExp = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))/;

    return (ipAddressFamily == "udp4" ? ipv4RegExp.test(ipAddress) : ipv6RegExp.test(ipaddress));
}

DtlsSocket.prototype.close = function(callback) {
    this.socket.close(callback);
}

DtlsSocket.prototype.ref = function() {
    this.socket.ref();

    return this;
}

DtlsSocket.prototype.unref = function() {
    this.socket.unref();

    return this;
}

DtlsSocket.prototype.send = function(msg, offset, length, port, host, pskIdentity, pskPassword, callback) {
    // search for an already-existing DtlsSession targeting the destination address/port with the same pskIdentity/pskPassword.
    let dtlsSession = null;
    let existingDtlsSessionFound = false;
    let thisObject = this;
    //
    let ipAddressFamily = this.socketType.toLowerCase();
    //
    let ipAddressResolvedCallback = function(err, addresses) {
        //
        if (err !== null) {
            switch (err.code) {
                default:
                    return;
            }
        }
        // retrieve the first ip address
        let ipAddress = addresses[0];
        //
        for (let iSession = 0; iSession < thisObject.dtlsSessions.length; iSession++) {
            let testSession = thisObject.dtlsSessions[iSession];
            if ((ipAddress === testSession.dstIpAddress) &&
                (port === testSession.dstPort) &&
                (pskIdentity === testSession.pskIdentity) &&
                (pskPassword === testSession.pskPassword)) {
                // we already have a session; capture it for reuse now
                dtlsSession = testSession;
                // we also set the existingDtlsSessionFound flag, so that we know the session is pre-existing (and may have timed out, requiring renegotiation)
                existingDtlsSessionFound = true; 
                break;
            }
        }

        // if we could not find a pre-existing DtlsSession, initiate one now.
        if (dtlsSession === null) {
            dtlsSession = DtlsSession.createDtlsSession(thisObject.socket, thisObject, thisObject.onApplicationDataMessage);
            thisObject.dtlsSessions.push(dtlsSession);
            dtlsSession.connect(port, ipAddress, pskIdentity, pskPassword, function() {
                /* connect listener */
                // send the message
                dtlsSession.sendApplicationData(msg);
            }, function(unused, disconnectedSession) {
                /* disconnect listener */
                for (let iSession = 0; iSession < thisObject.dtlsSessions.length; iSession++) {
                    if (thisObject.dtlsSessions[iSession] === disconnectedSession) {
                        // remove the array element
                        thisObject.dtlsSessions.splice(iSession, 1);
                        break;
                    }
                }
                /* disconnect our socket if it is not already disconnected */
                if (thisObject.socket !== null) {
                    try {
                        thisObject.socket.close();
                    }
                    catch(err) {
                        // ignore any errors closing socket
                    }
                };
            });
        } else {
            // send the message
            dtlsSession.sendApplicationData(msg);
        }
    }

    // resolve hostname to ipAddress if necessary; otherwise proceed with the properly-formatted ipAddress which was provided.
    if (!isIpAddress(ipAddressFamily, host)) {
        require('dns').resolve(host, (ipAddressFamily == "udp4" ? "A" : "AAAA"), ipAddressResolvedCallback);
    } else {
        ipAddressResolvedCallback(null, [host]);
    }

}

DtlsSocket.prototype.onSocketMessage = function(thisObject, msg, rinfo) {
    // search for the target DtlsSession
    let dtlsSession = null;
    for (let iSession = 0; iSession < thisObject.dtlsSessions.length; iSession++) {
        let testSession = thisObject.dtlsSessions[iSession];
        if ((rinfo.address === testSession.dstIpAddress) &&
            (rinfo.port === testSession.dstPort)) {
            // we already have a session; capture it for reuse now
            dtlsSession = testSession;
            break;
        }
    }

    if (dtlsSession !== null) {
        dtlsSession.onSocketMessage(msg, rinfo);
    }
}

DtlsSocket.prototype.onApplicationDataMessage = function(thisObject, dtlsSession, data) {
    if (thisObject.messageListener) {
        let rinfo = {
            address: dtlsSession.dstIpAddress,
            port: dtlsSession.dstPort,
            size: data.length
        };
        thisObject.messageListener(thisObject.callbackObject, data, rinfo);
    }
}