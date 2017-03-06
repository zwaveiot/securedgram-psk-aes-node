# securedgram-psk-aes
A partial DTLS 1.0 implementation for Node.js. Unofficial library, not supported by Sigma Designs.

This 'securedgram' library is designed to be a mostly-drop-in replacement for the standard node.js 'dgram' library.

This library supports DTLS 1.0 and the following ciphersuites:
* TLS_PSK_WITH_AES_128_CBC_SHA
* TLS_PSK_WITH_AES_256_CBC_SHA

#### To install the library
> npm install securedgram-psk-aes  

#### To import the library
> let securedgram = require('securedgram-psk-aes');  

#### To create a socket instance
> let dtlsSocket = securedgram.createDtlsSocket(ipAddressFamily, callbackObject, callback);
* ipAddressFamily options: ['udp4', 'udp6']  
* callbackObject: OPTIONAL object passed in first parameter of callback to tag this socket  
* callback: OPTIONAL callback, called when a message is received  

#### To send a message
> dtlsSocket.send(message, offset, length, port, host, pskIdentity, pskPassword, callback);
* message: buffer containing message to send  
* offset: offset (within buffer)  
* length: length (within buffer)  
* port: port #  
* host: hostname or ip address  
* pskIdentity: PSK "identity" parameter  
* pskPassword: Pre-shared key ("PSK password")  
* callback: OPTIONAL callback  

#### To receive a message (via createDtlsSocket-specified callback)
> let onMessage = function(callbackObject, data, rinfo) {  
> &nbsp;&nbsp;&nbsp;&nbsp;// handle message here  
> }  
###### NOTE: the developer must pass this function as the callback parameter when instantiating the DtlsSocket.

#### To close a socket instance
> dtlsSocket.close(callback);  
