# BurpKit

## Introduction
Welcome to the next generation of web application penetration testing - using WebKit to own the web.
BurpKit is a BurpSuite plugin which helps in assessing complex web apps that render the contents of
their pages dynamically. It also provides a bi-directional JavaScript bridge API which allows users
to create quick one-off BurpSuite plugin prototypes which can interact directly with the DOM and
Burp's extender API.

---

## System Requirements
BurpKit has the following system requirements:
- Oracle JDK &gt;=8u50 and &lt;9 ([Download](http://www.oracle.com/technetwork/java/javase/downloads/index.html))
- At least 4GB of RAM

---

## Installation
Installing BurpKit is simple:

1. Download the latest prebuilt release from the [GitHub releases page](https://github.com/allfro/BurpKit/releases).
2. Open BurpSuite and navigate to the `Extender` tab.
3. Under `Burp Extensions` click the `Add` button.
4. In the `Load Burp Extension` dialog, make sure that `Extension Type` is set to `Java` and click the `Select file ...` button under `Extension Details`.
5. Select the `BurpKit-<version>.jar` file and click `Next` when done.

If all goes well, you will see three additional top-level tabs appear in BurpSuite:

1.  `BurpKitty`: a courtesy browser for navigating the web within BurpSuite.
2.  `BurpScript IDE`: a lightweight integrated development environment for writing JavaScript-based BurpSuite plugins and other things.
3.  `Jython`: an integrated python interpreter console and lightweight script text editor.

---

## BurpScript
**BurpScript** enables users to write desktop-based JavaScript applications as well as BurpSuite extensions using the JavaScript scripting language. This is achieved by injecting two new objects by default into the DOM on page load:

1.  `burpKit`: provides numerous features including file system I/O support and easy JS library injection.
2. `burpCallbacks`: the JavaScript equivalent of the `IBurpExtenderCallbacks` interface in `Java` with a few slight modifications.

---

## `burpCallbacks` JavaScript Object
For the most part, the `burpCallbacks` object adheres to the `IBurpExtenderCallbacks` API detailed in [BurpSuite's documentation](https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html). In short, the following differences can be observed:

1.  All constants (i.e. `PARAM_XML`, `CONTENT_TYPE_UNKNOWN`, `INS_HEADER`, etc.) can be found as read-only properties within the `burpCallbacks` object (i.e. `burpCallbacks.PARAM_XML`).
2. GUI-based BurpSuite extensions that operate in the `SWING` thread have slightly modified APIs to avoid deadlocks caused by event loop inter-weaving.
3. Additional helper functions have been provided to ease and augment the interaction between JavaScript and BurpSuite.
4. Methods with the same name but multiple signatures (i.e. `foo(String)`, `foo(String, int)`, etc.) are numbered due to limitations within JavaScript (i.e. `foo(String)`, `foo2(String, int)`, etc.).

The following subsections detail the `burpCallbacks` API and provide brief examples.

---

### Methods
#### `setExtensionName(String name)` method
Sets the name of the BurpKit extension since all BurpScript extensions are operating under the context of the BurpKit plugin.

**Parameters:**
*  `name`: the name you wish to set for this extension.

**Example:**
```javascript
burpCallbacks.setExtensionName('foo');
```

---

#### `getHelpers()` method
Returns an instance of the `ExtensionHelpersBridge` object, which adheres to the API of the [IExtensionHelpers](https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html) interface with a few minor exceptions. See (`ExtensionHelpersBridge`)[#extensionshelpersbridge] for more details.

**Returns:**
An `ExtensionHelpersBridge` object.

**Example:**
```javascript
var helpers = burpCallbacks.getHelpers();
helpers.urlDecode('%3cscript%3e'); // returns '<script>'
```

---

## `ExtensionHelpersBridge` class
The `ExtensionHelpersBridge` is essentially an instance of the BurpSuite `IExtensionHelpers` object with a few minor exceptions to work-around the limitations within the JavaScript scripting language with regards to method overloading.  The helper object can be retrieved using the `burpCallbacks.getHelpers()` method.

---
### Methods
#### `analyzeRequest(Object request)` method
This method can be used to analyze an HTTP request, and obtain various key details about it.  The resulting `IRequestInfo` object will not include the full request URL if `request` is not an `IHttpRequestResponse` object. Alternatively, one can obtain the full URL by using the `analyzeRequest2()` method. 

**Parameters:**
*  `request` - A Java `byte[]` array, `String`, or `IHttpRequestResponse` object containing the request to be analyzed.

**Returns:**
An `IRequestInfo` object that can be queried to obtain details about the request.

**Example:**
```javascript
var helpers = burpCallbacks.getHelpers();
var requestInfo = helpers.analyzeRequest('GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n');
requestInfo.getMethod(); // returns 'GET'
```

---

#### `analyzeRequest2(IHttpService httpService, Object request)` method
This method can be used to analyze an HTTP request, and obtain various key details about it.

**Parameters:**
*  `httpService` - The HTTP service associated with the request. This is optional and may be `null`, in which case the resulting `IRequestInfo` object will not include the full request URL.
*  `request` - A Java `byte[]` array, or a `String` the request to be analyzed.

**Returns:**
An `IRequestInfo` object that can be queried to obtain details about the request.

**Example:**
```javascript
var helpers = burpCallbacks.getHelpers();
var requestInfo = helpers.analyzeRequest('GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n');
requestInfo.getMethod(); // returns 'GET'
```

---

#### `analyzeResponse(Object response)` method
This method can be used to analyze an HTTP response, and obtain various key details about it.

**Parameters:**
*  `response` - a Java `byte[]` array, or a `String` containing the response to be analyzed.

**Returns:**
An `IResponseInfo` object that can be queried to obtain details about the response.

**Example:**
```javascript
var responseInfo = helpers.analyzeResponse('HTTP/1.1 200 OK\r\nDate: Fri, 06 Nov 2009 00:35:42 GMT\r\nServer: Apache\r\nContent-Length: 0\r\nKeep-Alive: timeout=15, max=100\r\nConnection: Keep-Alive\r\nContent-Type: text/plain\r\n\r\n');
responseInfo.getStatusCode(); // returns 200
```

---

#### `getRequestParameter(Object request, String parameterName)` method
This method can be used to retrieve details of a specified parameter within an HTTP request. **Note:** Use `analyzeRequest()` to obtain details of all parameters within the request. 

**Parameters:**
*  `request` - a Java `byte[]` array or a `String` containing the request to be inspected for the specified parameter..
* `parameterName` - The name of the parameter to retrieve.

**Returns:**
An `IParameter` object that can be queried to obtain details about the parameter, or `null` if the parameter was not found.

**Example:**
```javascript
var parameter = helpers.getRequestParameter('GET /?q=foo HTTP/1.1\r\nHost: www.bar.com\r\n\r\n', 'q');
parameter.getValue(); // returns 'foo'
```

---

#### `urlDecode(String data)` method
This method can be used to URL-decode the specified data.

**Example:**
```javascript
helpers.urlDecode('%3cscript%3e'); // returns '<script>'
```

---

#### `urlDecode2(Object data)` method
This method can be used to URL-decode the specified data. 

**Parameters:**
*  `data` - a Java `byte[]` array or a `String` containing the data to be URL decoded.

**Returns:**
The decoded data.

**Example:**
```javascript
helpers.urlDecode2('f%2fb'); // returns Java byte[]{'f', '/', 'b'}
```

---

#### `urlEncode(String data)` method
This method can be used to URL-encode the specified data. Any characters that do not need to be encoded within HTTP requests are not encoded.

**Parameters:**
*  `data` - The data to be URL encoded.

**Returns:**
The encoded data.

**Example:**
```javascript
helpers.urlEncode('foo/bar');  // returns 'foo%2fbar'
```

---

#### `urlEncode2(Object data)` method
This method can be used to URL-encode the specified data. Any characters that do not need to be encoded within HTTP requests are not encoded. 

**Parameters:**
*  `data` - a Java `byte[]` array or a `String` containing the data to be URL encoded.

**Returns:**
The encoded data.

**Example:**
```javascript
helpers.urlEncode2('f/b'); // returns Java byte[] {'f', '%', '2', 'f', 'b'}
```

---

#### `base64Decode(Object data)` method
This method can be used to Base64-encode the specified data. `data` can be a Java `byte[]` array or a `String`.

**Parameters:**
*  `data` - a Java `byte[]` array or a `String` containing the data to be Base64 decoded.

**Returns:**
The decoded data.

**Example:**
```javascript
helpers.base64Decode('Zm9v'); // returns Java byte[] {'f', 'o', 'o'}
```

---

#### `base64Decode2(Object data)` method
This method can be used to Base64-encode the specified data. 

**Parameters:**
*  `data` - a Java `byte[]` array or a `String` containing the data to be Base64 decoded.

**Returns:**
The decoded data.

**Example:**
```javascript
helpers.base64Decode2('Zm9v'); // returns 'foo'
```

---

#### `base64Encode(Object data)` method
This method can be used to Base64-encode the specified data. `data` can either be a Java `byte[]` array or a `String`.

**Example:**
```javascript
helpers.base64Encode('foo'); // returns 'Zm9v'
```

---

#### `stringToBytes(String data)` method
This method can be used to convert data from String form into an array of bytes. The conversion does not reflect any particular character set, and a character with the hex representation `0xWXYZ` will always be converted into a byte with the representation `0xYZ`. It performs the opposite conversion to the method `bytesToString()`, and byte-based data that is converted to a String and back again using these two methods is guaranteed to retain its integrity (which may not be the case with conversions that reflect a given character set).

**Parameters:**
*  `data` - The data to be converted.

**Returns:**
The converted data.

**Example:**
```javascript
helpers.stringToBytes('abc'); // returns Java byte[] {'a', 'b', 'c'}
```

---

#### `bytesToString(byte[] data)` method
This method can be used to convert data from an array of bytes into String form. The conversion does not reflect any particular character set, and a byte with the representation `0xYZ` will always be converted into a character with the hex representation `0x00YZ`. It performs the opposite conversion to the method `stringToBytes()`, and byte-based data that is converted to a String and back again using these two methods is guaranteed to retain its integrity (which may not be the case with conversions that reflect a given character set).

**Parameters:**
*  `data` - The data to be converted.

**Returns:**
The converted data.

**Example:**
```javascript
helpers.bytesToString(helpers.stringToBytes('abc')); // returns 'abc'
```

---

#### `indexOf(Object data, Object pattern, boolean caseSensitive, int from, int to)` method
This method searches a piece of data for the first occurrence of a specified pattern. It works on byte-based data in a way that is similar to the way the native Java method `String.indexOf()` works on String-based data.

**Parameters:**
*  `data` - A Java `byte[]` arrays or `String` containing the data to be searched.
*  `pattern` - A Java `byte[]` arrays or `String` containing the pattern to be searched for.
*  `caseSensitive` - Flags whether or not the search is case-sensitive.
*  `from` - The offset within data where the search should begin.
*  `to` - The offset within data where the search should end.

**Returns:**
The offset of the first occurrence of the pattern within the specified bounds, or `-1` if no match is found.

**Example:**
```javascript
helpers.indexOf('GET /?q=foo HTTP/1.1\r\n', '/?q=foo', true, 0, 10); // returns 5;
helpers.indexOf('GET /?q=foo HTTP/1.1\r\n', '/?Q=foo', true, 0, 10); // returns -1;
```

---

#### `buildHttpMessage(Object headers, Object body)` method
This method builds an HTTP message containing the specified headers and message body. If applicable, the Content-Length header will be added or updated, based on the length of the body. `body` can be either a Java `byte[]` array or a `String`

**Parameters:**
*  `headers` - A Java `List<String>` or a JavaScript `String` array containing the headers to include in the message.
*  `body` - The body of the message, of null if the message has an empty body.

**Returns:**
The resulting full HTTP message.

**Example:**
```javascript
var message = helpers.buildHttpMessage(['GET / HTTP/1.1', 'Host: foo.com'], ''); // returns a Java byte[] array containing HTTP request
```

---

#### `buildHttpRequest(String url)` method
This method creates a GET request to the specified URL. The headers used in the request are determined by the Request headers settings as configured in Burp Spider's options.

**Parameters:**
*  `url` - a `String` containing the URL to which the request should be made.

**Returns:**
A request to the specified URL.

**Example:**
```javascript
var message = helpers.buildHttpRequest('http://www.bar.com');
```

---

#### `addParameter(Object request, IParameter parameter)` method
This method adds a new parameter to an HTTP request, and if appropriate updates the Content-Length header.  See `buildParameter()` for information on building parameters.

**Parameters**:
*  `request` - a Java `byte[]` array or a `String` containing the request to which the parameter should be added.
* `parameter` - An IParameter object containing details of the parameter to be added. Supported parameter types are: `PARAM_URL`, `PARAM_BODY` and `PARAM_COOKIE`.

**Returns**:
A new HTTP request with the new parameter added.

**Example:**
```javascript
var newMessage = helpers.addParameter(
	'GET / HTTP/1.1\r\nHost: www.foo.com\r\n\r\n',
	helpers.buildParameter('q', 'bar', burpCallbacks.PARAM_URL)
); // returns 'GET /?q=bar' HTTP request.
```

---

#### `removeParameter(Object request, IParameter parameter)` method
This method removes a parameter from an HTTP request, and if appropriate updates the Content-Length header.

**Parameters:**
*  `request` - a Java `byte[]` array or a `String` containing the request from which the parameter should be removed.
* `parameter` - An IParameter object containing details of the parameter to be removed. Supported parameter types are: `PARAM_URL`, `PARAM_BODY` and `PARAM_COOKIE`.

**Returns:**
A new HTTP request with the parameter removed.

**Example:**
```javascript
var request = 'GET /?q=bar HTTP/1.1\r\nHost: www.foo.com\r\n\r\n';
var requestInfo = helpers.analyzeRequest(request); // parse the request
var parameters = requestInfo.getParameters(); // get its parameters
var newMessage = helpers.removeParameter(
	message, 
	parameters[0]
); // remove 'q' parameter from GET request
```

---

#### `updateParameter(Object request, IParameter parameter)` method
This method updates the value of a parameter within an HTTP request, and if appropriate updates the `Content-Length` header. Note: This method can only be used to update the value of an existing parameter of a specified type. If you need to change the type of an existing parameter, you should first call `removeParameter()` to remove the parameter with the old type, and then call `addParameter()` to add a parameter with the new type. 

**Parameters**:
* `request` - The request containing the parameter to be updated as a Java `byte[]` array or a `String`.
* `parameter` - An IParameter object containing details of the parameter to be updated. Supported parameter types are: `PARAM_URL`, `PARAM_BODY` and `PARAM_COOKIE`.
 
 **Returns**:
 A new HTTP request with the parameter updated.

**Example:**
```javascript
var request = 'GET /?q=bar HTTP/1.1\r\nHost: www.foo.com\r\n\r\n';
var newMessage = helpers.updateParameter(
	message, 
	helpers.buildParameter('q', 'bar2')
); // updates value of 'q' parameter to 'bar2'
```

---

#### `toggleRequestMethod(Object request)` method
This method can be used to toggle a request's method between `GET` and `POST`. Parameters are relocated between the URL query string and message body as required, and the `Content-Length` header is created or removed as applicable. 

**Parameters**:
*  `request` - a Java `byte[]` array or `String` containing the HTTP request whose method should be toggled.

**Returns:**
A new HTTP request using the toggled method.

**Example:**
```javascript
var request = 'GET /?q=bar HTTP/1.1\r\nHost: www.foo.com\r\n\r\n'; 
request = helpers.toggleRequestMethod(request); // Changes GET to POST request
```

---

#### `buildHttpService(String host, int port, String protocol)` method
This method constructs an `IHttpService` object based on the details provided.

**Parameters**:
*  `host` - The HTTP service host.
*  `port` - The HTTP service port.
*  `protocol` - The HTTP service protocol (i.e. `'http'` or `'https'`).

**Returns:**
An `IHttpService` object based on the details provided.

**Example:**
```javascript
var httpService = helpers.buildHttpService('foo.com', 80, 'http');
```

---

#### `buildHttpService2(String host, int port, boolean useHttps)` method
This method constructs an `IHttpService` object based on the details provided.

**Parameters**:
*  `host` - The HTTP service host.
*  `port` - The HTTP service port.
*  `useHttps` - Flags whether the HTTP service protocol is HTTPS or HTTP.

**Returns:**
An `IHttpService` object based on the details provided.

**Example:**
```javascript
var httpService = helpers.buildHttpService2('foo.com', 80, true); // SSL enabled service
```

---

#### `buildParameter(String name, String value, int type)` method
This method constructs an `IParameter` object based on the details provided.

**Parameters:**
*  `name` - The parameter name.
*  `value` - The parameter value.
*  `type` - The parameter type, as defined in the `burpCallbacks` object beginning with the `PARAM_` prefix.

**Returns:**
An `IParameter` object based on the details provided.

**Example:**
```javascript
var parameter = helpers.buildParameter('foo', 'bar', burpCallbacks.PARAM_URL); // builds a GET parameter 'foo=bar'
```

---

#### `makeScannerInsertionPoint(String insertionPointName, Object baseRequest, int from, int to)` method
This method constructs an `IScannerInsertionPoint` object based on the details provided. It can be used to quickly create a simple insertion point based on a fixed payload location within a base request.

**Parameters:**
*  `insertionPointName` - The name of the insertion point.
*  `baseRequest` - A Java `byte[]` array or `String` containing the request from which to build scan requests.
*  `from` - The offset of the start of the payload location.
*  `to` - The offset of the end of the payload location.

**Returns:**
An `IScannerInsertionPoint` object based on the details provided.

**Example:**
```javascript
var request = 'GET /?q=bar HTTP/1.1\r\nHost: foo.com\r\n\r\n'
var requestInfo = helpers.analyzeRequest(request);

// get 'q' parameter
var parameter = requestInfo.getParameters()[0];

var insertionPoint = helpers.makeScannerInsertionPoint(
	'"q" Parameter Insertion Point', 
	request,
	parameter.getValueStart(),
	parameter.getValueEnd()
); // defines value of 'q' parameter ('bar') as insertion point
```

---

## Compiling BurpKit
BurpKit is distributed as an [IntelliJ IDEA](https://www.jetbrains.com/idea/) project. Once the project is opened in IntelliJ, compilation should be trivial. The JAR file can be built using the `Build Artifacts...` menu item under the `Build` menu. The compiled output will appear under the `out` directory.

---

## Known Issues
The following sections detail known issues that have been discovered within BurpKit and possible workarounds.

---

### No Upstream Proxy Support
Upstream proxies set within BurpSuite's `Options` tab are currently not supported as there exists no way to monitor BurpSuite setting modifications. Therefore, upstream proxies will have to be configured at the system level or via the Java command line arguments. BurpKit may leverage BurpSuite's internal request framework in future releases.

---

### Blank Tabs
Unhandled exceptions within the JavaFX event loop may trigger this condition. Currently, BurpKit-v1.01-pre attempts to resolve this issue. If you are still experiencing this issue, please run BurpSuite from the command line (e.g. `java -jar burpsuite_<version>.jar -Xmx4g`)  and [open a GitHub issue](https://github.com/allfro/BurpKit/issues/new) with the following details:

1.  OS and system details (please include RAM size);
2.  Console output, if any;
2.  Java version (`java -version`); and
3.  BurpSuite runtime arguments, if applicable.

---
