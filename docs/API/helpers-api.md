## `analyzeRequest(Object request)` 
This method can be used to analyze an HTTP request, and obtain various key details about it.  The resulting `IRequestInfo` object will not include the full request URL if `request` is not an `IHttpRequestResponse` object. Alternatively, one can obtain the full URL by using the `analyzeRequest2()` method. 

**Parameters:**

*  `request` - A Java `byte[]`, `String`, or `IHttpRequestResponse` object containing the request to be analyzed.

**Returns:**
An `IRequestInfo` object that can be queried to obtain details about the request.

**Example:**
```javascript
var requestInfo = helpers.analyzeRequest('GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n');
requestInfo.getMethod(); // returns 'GET'
```

---

## `analyzeRequest2(IHttpService httpService, Object request)`
This method can be used to analyze an HTTP request, and obtain various key details about it.

**Parameters:**

*  `httpService` - The HTTP service associated with the request. This is optional and may be `null`, in which case the resulting `IRequestInfo` object will not include the full request URL.
*  `request` - A Java `byte[]` or `String` object the request to be analyzed.

**Returns:**
An `IRequestInfo` object that can be queried to obtain details about the request.

**Example:**
```javascript
var requestInfo = helpers.analyzeRequest('GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n');
requestInfo.getMethod(); // returns 'GET'
```

---

## `analyzeResponse(Object response)`
This method can be used to analyze an HTTP response, and obtain various key details about it.

**Parameters:**

*  `response` - a Java `byte[]` or `String` object containing the response to be analyzed.

**Returns:**
An `IResponseInfo` object that can be queried to obtain details about the response.

**Example:**
```javascript
var responseInfo = helpers.analyzeResponse('HTTP/1.1 200 OK\r\nDate: Fri, 06 Nov 2009 00:35:42 GMT\r\nServer: Apache\r\nContent-Length: 0\r\nKeep-Alive: timeout=15, max=100\r\nConnection: Keep-Alive\r\nContent-Type: text/plain\r\n\r\n');
responseInfo.getStatusCode(); // returns 200
```

---

## `getRequestParameter(Object request, String parameterName)`
This method can be used to retrieve details of a specified parameter within an HTTP request. **Note:** Use `analyzeRequest()` to obtain details of all parameters within the request. 

**Parameters:**

*  `request` - a Java `byte[]` or `String` object containing the request to be inspected for the specified parameter..
* `parameterName` - The name of the parameter to retrieve.

**Returns:**
An `IParameter` object that can be queried to obtain details about the parameter, or `null` if the parameter was not found.

**Example:**
```javascript
var parameter = helpers.getRequestParameter('GET /?q=foo HTTP/1.1\r\nHost: www.bar.com\r\n\r\n', 'q');
parameter.getValue(); // returns 'foo'
```

---

## `urlDecode(String data)`
This method can be used to URL-decode the specified data.

**Parameters:**

*  `data` - a Java `byte[]` or `String` object containing the data to be URL decoded.


**Returns:**
The decoded data as a `String`.

**Example:**
```javascript
helpers.urlDecode('%3cscript%3e'); // returns '<script>'
```

---

## `urlDecode2(Object data)`
This method can be used to URL-decode the specified data. 

**Parameters:**

*  `data` - a Java `byte[]` or `String` object containing the data to be URL decoded.

**Returns:**
The decoded data as a `byte[]`.

**Example:**
```javascript
helpers.urlDecode2('f%2fb'); // returns Java byte[]{'f', '/', 'b'}
```

---

## `urlEncode(String data)`
This method can be used to URL-encode the specified data. Any characters that do not need to be encoded within HTTP requests are not encoded.

**Parameters:**

*  `data` - The data to be URL encoded.

**Returns:**
The encoded data as a `String`.

**Example:**
```javascript
helpers.urlEncode('foo/bar');  // returns 'foo%2fbar'
```

---

## `urlEncode2(Object data)`
This method can be used to URL-encode the specified data. Any characters that do not need to be encoded within HTTP requests are not encoded. 

**Parameters:**

*  `data` - a Java `byte[]` or `String` object containing the data to be URL encoded.

**Returns:**
The encoded data as a `byte[]`.

**Example:**
```javascript
helpers.urlEncode2('f/b'); // returns Java byte[] {'f', '%', '2', 'f', 'b'}
```

---

## `base64Decode(Object data)`
This method can be used to Base64-encode the specified data. `data` can be a Java `byte[]` array or a `String`.

**Parameters:**

*  `data` - a Java `byte[]` or `String` object containing the data to be Base64 decoded.

**Returns:**
The decoded data as a `byte[]`.

**Example:**
```javascript
helpers.base64Decode('Zm9v'); // returns Java byte[] {'f', 'o', 'o'}
```

---

## `base64Decode2(Object data)`
This method can be used to Base64-encode the specified data. 

**Parameters:**

*  `data` - a Java `byte[]` or `String` object containing the data to be Base64 decoded.

**Returns:**
The Base64 decoded data as a `String`.

**Example:**
```javascript
helpers.base64Decode2('Zm9v'); // returns 'foo'
```

---

## `base64Encode(Object data)`
This method can be used to Base64-encode the specified data. `data` can either be a Java `byte[]` array or a `String`.

* `data` - Java `byte[]` or `String` object containin the data to be Base64 encoded.

**Returns:**
The Base64 encoded data.

**Example:**
```javascript
helpers.base64Encode('foo'); // returns 'Zm9v'
```

---

## `stringToBytes(String data)`
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

## `bytesToString(byte[] data)`
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

## `indexOf(Object data, Object pattern, boolean caseSensitive, int from, int to)`
This method searches a piece of data for the first occurrence of a specified pattern. It works on byte-based data in a way that is similar to the way the native Java method `String.indexOf()` works on String-based data.

**Parameters:**

*  `data` - A Java `byte[]` or `String` object containing the data to be searched.
*  `pattern` - A Java `byte[]` or `String` object containing the pattern to be searched for.
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

## `buildHttpMessage(Object headers, Object body)`
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

## `buildHttpRequest(String url)`
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

## `addParameter(Object request, IParameter parameter)`
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

## `removeParameter(Object request, IParameter parameter)`
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

## `updateParameter(Object request, IParameter parameter)`
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

## `toggleRequestMethod(Object request)`
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

## `buildHttpService(String host, int port, String protocol)`
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

## `buildHttpService2(String host, int port, boolean useHttps)`
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

## `buildParameter(String name, String value, int type)`
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

## `makeScannerInsertionPoint(String insertionPointName, Object baseRequest, int from, int to)`
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


