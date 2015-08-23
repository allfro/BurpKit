All of the various BurpSuite constants can be found as fields or properties within the `burpCallbacks` object and can be accessed like so:

```javascript
burpCallbacks.TOOL_COMPARER
burpCallbacks.PARAM_BODY
// etc.
```

--- 

# Tool Flags

*  `TOOL_COMPARER` - Flag used to identify the Burp Comparer tool.
*  `TOOL_DECODER` - Flag used to identify the Burp Decoder tool.
*  `TOOL_EXTENDER` - Flag used to identify the Burp Extender tool.
*  `TOOL_INTRUDER` - Flag used to identify the Burp Intruder tool.
*  `TOOL_PROXY` - Flag used to identify the Burp Proxy tool.
*  `TOOL_REPEATER` - Flag used to identify the Burp Repeater tool.
*  `TOOL_SCANNER` - Flag used to identify the Burp Scanner tool.
*  `TOOL_SEQUENCER` - Flag used to identify the Burp Sequencer tool.
*  `TOOL_SPIDER` - Flag used to identify the Burp Spider tool.
*  `TOOL_SUITE` - Flag used to identify Burp Suite as a whole.
*  `TOOL_TARGET` - Flag used to identify the Burp Target tool.

---

# Parameter Types

*  `PARAM_BODY` - Used to indicate a parameter within the message body.
*  `PARAM_COOKIE` - Used to indicate an HTTP cookie.
*  `PARAM_JSON` - Used to indicate an item of data within a JSON structure.
*  `PARAM_MULTIPART_ATTR` - Used to indicate the value of a parameter attribute within a multi-part message body (such as the name of an uploaded file).
*  `PARAM_URL` - Used to indicate a parameter within the URL query string.
*  `PARAM_XML` - Used to indicate an item of data within an XML structure.
*  `PARAM_XML_ATTR` - Used to indicate the value of a tag attribute within an XML structure.

---

# Context Menu Invocation Types

*  `CONTEXT_INTRUDER_ATTACK_RESULTS` - Used to indicate that the context menu is being invoked in an Intruder attack results.
*  `CONTEXT_INTRUDER_PAYLOAD_POSITIONS` - Used to indicate that the context menu is being invoked in the Intruder payload positions editor.
*  `CONTEXT_MESSAGE_EDITOR_REQUEST` - Used to indicate that the context menu is being invoked in a request editor.
*  `CONTEXT_MESSAGE_EDITOR_RESPONSE` - Used to indicate that the context menu is being invoked in a response editor.
*  `CONTEXT_MESSAGE_VIEWER_REQUEST` - Used to indicate that the context menu is being invoked in a non-editable request viewer.
*  `CONTEXT_MESSAGE_VIEWER_RESPONSE` - Used to indicate that the context menu is being invoked in a non-editable response viewer.
*  `CONTEXT_PROXY_HISTORY` - Used to indicate that the context menu is being invoked in the Proxy history.
*  `CONTEXT_SCANNER_RESULTS` - Used to indicate that the context menu is being invoked in the Scanner results.
*  `CONTEXT_SEARCH_RESULTS` - Used to indicate that the context menu is being invoked in a search results window.
*  `CONTEXT_TARGET_SITE_MAP_TABLE` - Used to indicate that the context menu is being invoked in the Target site map table.
*  `CONTEXT_TARGET_SITE_MAP_TREE` - Used to indicate that the context menu is being invoked in the Target site map tree.

---

# Action Types

*  `ACTION_DO_INTERCEPT` - This action causes Burp Proxy to present the message to the user for manual review or modification.
*  `ACTION_DO_INTERCEPT_AND_REHOOK` - This action causes Burp Proxy to present the message to the user for manual review or modification, and then make a second call to processProxyMessage.
*  `ACTION_DONT_INTERCEPT` - This action causes Burp Proxy to forward the message to the remote server or client, without presenting it to the user.
*  `ACTION_DONT_INTERCEPT_AND_REHOOK` - This action causes Burp Proxy to skip user interception, and then make a second call to processProxyMessage.
*  `ACTION_DROP` - This action causes Burp Proxy to drop the message.
*  `ACTION_FOLLOW_RULES` - This action causes Burp Proxy to follow the current interception rules to determine the appropriate action to take for the message.
*  `ACTION_FOLLOW_RULES_AND_REHOOK` - This action causes Burp Proxy to follow the current interception rules to determine the appropriate action to take for the message, and then make a second call to processProxyMessage.

---

# Scanner Insertion Point Types

*  `INS_EXTENSION_PROVIDED` - Used to indicate where the insertion point is provided by an extension-registered IScannerInsertionPointProvider.
*  `INS_HEADER` - Used to indicate where the payload is inserted into the value of an HTTP request header.
*  `INS_PARAM_AMF` - Used to indicate where the payload is inserted into the value of an AMF parameter.
*  `INS_PARAM_BODY` - Used to indicate where the payload is inserted into the value of a body parameter.
*  `INS_PARAM_COOKIE` - Used to indicate where the payload is inserted into the value of an HTTP cookie.
*  `INS_PARAM_JSON` - Used to indicate where the payload is inserted into the value of an item of data within a JSON structure.
*  `INS_PARAM_MULTIPART_ATTR` - Used to indicate where the payload is inserted into the value of a parameter attribute within a multi-part message body (such as the name of an uploaded file).
*  `INS_PARAM_NAME_BODY` - Used to indicate where the payload is inserted into the name of an added body parameter.
*  `INS_PARAM_NAME_URL` - Used to indicate where the payload is inserted into the name of an added URL parameter.
*  `INS_PARAM_URL` - Used to indicate where the payload is inserted into the value of a URL parameter.
*  `INS_PARAM_XML` - Used to indicate where the payload is inserted into the value of an item of data within an XML data structure.
*  `INS_PARAM_XML_ATTR` - Used to indicate where the payload is inserted into the value of a tag attribute within an XML structure.
*  `INS_UNKNOWN` - Used to indicate where the payload is inserted at an unknown location within the request.
*  `INS_URL_REST` - Used to indicate where the payload is inserted into a REST parameter within the URL file path.
*  `INS_USER_PROVIDED` - Used to indicate where the payload is inserted at a location manually configured by the user.
