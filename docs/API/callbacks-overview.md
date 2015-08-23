The `burpCallbacks` object is automatically injected into the DOM every time a `document.onload` event is triggered. For the most part, the `burpCallbacks` object adheres to the `IBurpExtenderCallbacks` API detailed in [BurpSuite's documentation](https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html). In short, the following differences can be observed:

1.  All constants (i.e. `PARAM_XML`, `CONTENT_TYPE_UNKNOWN`, `INS_HEADER`, etc.) can be found as read-only properties within the `burpCallbacks` object (i.e. `burpCallbacks.PARAM_XML`).
2. GUI-based BurpSuite extensions that operate in the `SWING` thread have slightly modified APIs to avoid deadlocks caused by event loop inter-weaving.
3. Additional helper functions have been provided to ease and augment the interaction between JavaScript and BurpSuite.
4. Methods with the same name but multiple signatures (i.e. `foo(String)`, `foo(String, int)`, etc.) are numbered due to limitations within JavaScript (i.e. `foo(String)`, `foo2(String, int)`, etc.).

The following example demonstrates how one could easily create a simple proxy listener using JavaScript with the BurpKit extensions:

```javascript
// inject an HTTP helper library for message parsing
burpKit.requireLib('httplib');

// Get our burp helpers
var helpers = burpCallbacks.getHelpers();

// Register our proxy listener
burpCallbacks.registerProxyListener(function(isRequest, message) {
  var messageInfo = message.getMessageInfo();
  if (isRequest) {
    var request = httplib.parseRequest(helpers.bytesToString(messageInfo.getRequest()));
    alert(">> " + request.method + " " + messageInfo.getUrl().toString());
  } else {            
    var response = httplib.parseResponse(helpers.bytesToString(messageInfo.getResponse()));
    alert("<< " + response.statusCode + " " + response.statusMessage);
  }
});
```

This is just a simple example of how powerful BurpKit is. Many more examples can be found in the bundled [examples](https://github.com/allfro/BurpKit/tree/master/examples) directory that comes with BurpKit. The following subsections detail the methods available within the `burpCallbacks` object.
