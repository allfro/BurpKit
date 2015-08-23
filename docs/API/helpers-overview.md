The `ExtensionHelpersBridge` is essentially an instance of the BurpSuite `IExtensionHelpers` object with a few minor exceptions to work-around the limitations within the JavaScript scripting language with regards to method overloading.  The helper object can be retrieved using the `burpCallbacks.getHelpers()` method. Although `ExtensionHelpersBridge` objects are only accessible from within the JavaScripting language, you'll notice that the parameters for some of these methods are strongly typed. This is done to support interaction between the JVM, specifically BurpSuite, and the JavaScript engine.

The following example demonstrates how one can use the `ExtensionHelpersBridge` object in JavaScript in very much the same way one uses the `IExtensionHelpers` object when writing Java plugins for BurpSuite:

```javascript
var helpers = burpCallbacks.getHelpers(); // get our instance of the ExtensionHelpersBridge.

var httpService = helpers.buildHttpService2('www.google.com', 80, true); 
var requestResponse = burpCallbacks.makeHttpRequest(
	httpService, 
	'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'
);

var responseInfo = burpCallbacks.analyzeResponse(requestResponse.getResponse());
alert("Received Status: " + responseInfo.getStatusCode());
```

