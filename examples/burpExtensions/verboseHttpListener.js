/*
 * BurpKit - WebKit-based penetration testing plugin for BurpSuite
 * Copyright (C) 2015  Red Canari, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * The following example demonstrates how to create a HTTP Listener using JavaScript.
 * The meat of the code is defined in the `httpListener` variable on line 26. As you
 * can see, the JavaScript object that we pass into `burpCallbacks.registerHttpListener()`
 * mimicks the interface of `burp.IHttpListener`. `burpCallbacks.registerHttpListener`
 * behaves in exactly the same manner as the Java version with one small difference -
 * an instance of `IHttpListener` is returned instead of nothing. This is done so that
 * we can remove the listener from BurpSuite, if necessary.
 */

// Here we check to see if `httpListenerObject` is defined. If so, this means we are
// re-running this script (maybe because we wanted to modify our original HTTP listener).
// If it does exist, then we remove the old HTTP listener to free up memory.
if ('httpListenerObject' in window) {
    alert('Removing previously defined HTTP listener');
    burpCallbacks.removeHttpListener(httpListenerObject);
}

// Load the `httplib` library that can handle parsing HTTP requests, responses, and headers
// if it hasn't been loaded already.
if (!('httplib' in window))
    burpKit.requireLib('httplib');

// This is our JavaScript-based HTTP object. As you can see, it defines a 
// `processHttpMessage` method just like a Java class that implements the
// `burp.IHttpListener` interface.
var httpListener = {
    'helpers': burpCallbacks.getHelpers(),
    'processHttpMessage': function(toolFlag, isRequest, messageInfo) {
        // TODO: put your code here :)
        
        if (isRequest) { 
            var request = httplib.parseRequest(this.helpers.bytesToString(messageInfo.getRequest()));
            alert(burpCallbacks.getToolName(toolFlag) + " >> " + request.method + " " + messageInfo.getUrl().toString());
        }
        else {            
            var response = httplib.parseResponse(this.helpers.bytesToString(messageInfo.getResponse()));
            alert(burpCallbacks.getToolName(toolFlag) + " << " + response.statusCode + " " + response.statusMessage + " (" + messageInfo.getUrl().toString() + ")");
        }
    }
};

// Finally, we register our JavaScript-based HTTP listener and we start to see our
// results. Hooray! 
// ****IMPORTANT NOTE****: since we are using JavaScript objects to emulate HTTP
// listeners, the HTTP listener will no longer work if the DOM is reset (i.e. 
// document.location='http://foo.com').
alert('Registering new HTTP listener');
httpListenerObject = burpCallbacks.registerHttpListener(httpListener);