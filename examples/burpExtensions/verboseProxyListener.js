/**
 * The following example demonstrates how to create a ProxyListener using JavaScript.
 * The meat of the code is defined in the `proxyListener` variable on line 26. As you
 * can see, the JavaScript object that we pass into `burpCallbacks.registerProxyListener()`
 * mimicks the interface of `burp.IProxyListener`. `burpCallbacks.registerProxyListener`
 * behaves in exactly the same manner as the Java version with one small difference -
 * an instance of `IProxyListener` is returned instead of nothing. This is done so that
 * we can remove the listener from BurpSuite, if necessary.
 */

// Here we check to see if `proxyListenerObject` is defined. If so, this means we are
// re-running this script (maybe because we wanted to modify our original proxy listener).
// If it does exist, then we remove the old proxy listener to free up memory.
if ('proxyListenerObject' in window) {
    alert('Removing previously defined proxy listener');
    burpCallbacks.removeProxyListener(proxyListenerObject);
}

// Load the `httplib` library that can handle parsing HTTP requests, responses, and headers
// if it hasn't been loaded already.
if (!('httplib' in window))
    burpKit.requireLib('httplib');

// This is our JavaScript-based proxy object. As you can see, it defines a 
// `processProxyMessage` method just like a Java class that implements the 
// `burp.IProxyListener` interface. 
var proxyListener = {
    'helpers': burpCallbacks.getHelpers(),
    'processProxyMessage': function(isRequest, message) {
        // TODO: put your code here :)
        var messageInfo = message.getMessageInfo();
        if (isRequest) { 
            var request = httplib.parseRequest(this.helpers.bytesToString(messageInfo.getRequest()));
            alert(">> " + request.method + " " + messageInfo.getUrl().toString());
        }
        else {            
            var response = httplib.parseResponse(this.helpers.bytesToString(messageInfo.getResponse()));
            alert("<< " + response.statusCode + " " + response.statusMessage + " (" + messageInfo.getUrl().toString() + ")");
        }
    }
};

// Finally, we register our JavaScript-based proxy listener and we start to see our
// results. Hooray! 
// ****IMPORTANT NOTE****: since we are using JavaScript objects to emulate proxy
// listeners, the proxy listener will no longer work if the DOM is reset (i.e. 
// document.location='http://foo.com').
proxyListenerObject = burpCallbacks.registerProxyListener(proxyListener);