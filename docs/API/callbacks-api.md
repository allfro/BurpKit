## `setExtensionName(String name)`
Sets the name of the BurpKit extension since all BurpScript extensions are operating under the context of the BurpKit plugin.

**Parameters:**

*  `name`: the name you wish to set for this extension.

**Example:**
```javascript
burpCallbacks.setExtensionName('foo');
```

---

## `getHelpers()`
Returns an instance of the `ExtensionHelpersBridge` object, which adheres to the API of the [IExtensionHelpers](https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html) interface with a few minor exceptions. See the [ExtensionHelpersBridge](/API/helpers/) page for more details on the API.

**Returns:**
An `ExtensionHelpersBridge` object.

**Example:**
```javascript
var helpers = burpCallbacks.getHelpers();
helpers.urlDecode('%3cscript%3e'); // returns '<script>'
```

---

## `getStdout()`
This method is used to obtain the current extension's standard output stream. Extensions should write all output
to this stream, allowing the Burp user to configure how that output is handled from within the UI.

**Returns:**
The extension's standard output stream.

**Example:**
```javascript
burpCallbacks.getStdout().write(
  burpCallbacks.getHelpers().stringToBytes('Hello World!\n')
);
```

---

## `getStderr()`
This method is used to obtain the current extension's standard error stream. Extensions should write all output
to this stream, allowing the Burp user to configure how that output is handled from within the UI.

**Returns:**
The extension's standard error stream.

**Example:**
```javascript
burpCallbacks.getStderr().write(
  burpCallbacks.getHelpers().stringToBytes('Hello World!\n')
);
```

---

## `printOutput(String message)`
This method prints a line of output to the current extension's standard output stream.

**Parameters:**

*  `message` - The message to print.

**Example:**
```javascript
burpCallbacks.printOutput("hello\n");
```

---

## `printError(String message)`
This method prints a line of output to the current extension's standard error stream.

**Parameters:**

*  `message` - The message to print.

**Example:**
```javascript
burpCallbacks.printError("hello\n");
```

---

## `registerExtensionStateListener(Object listener)`
This method is used to register a listener which will be notified of changes to the extension's state. **Note:** Any
extensions that start background threads or open system resources (such as files or database connections) should
register a listener and terminate threads / close resources when the extension is unloaded.

**Parameters:**

*  `listener` - An object created by the extension that implements the [IExtensionStateListener](https://portswigger.net/burp/extender/api/burp/IExtensionStateListener.html) interface or a lambda function that has the same prototype as the [IExtensionStateListener.extensionUnloaded()](https://portswigger.net/burp/extender/api/burp/IExtensionStateListener.html#extensionUnloaded()) method.


**Returns:**
The Java instance of `burp.IExtensionStateListener` that was registered.

**Example:**
```javascript
burpCallbacks.registerExtensionStateListener(function() { 
  alert('Extension Unloaded!');
});
```

or:

```javascript
burpCallbacks.registerExtensionStateListener({
  'extensionUnloaded': function() {
    alert('Extension Unloaded!');
  }
});
```

---

## `getExtensionStateListeners()`
This method is used to retrieve the extension state listeners that are registered by the extension.

**Returns:**
A list of extension state listeners that are currently registered by this extension.

**Example:**
```javascript
burpCallbacks.getExtensionStateListeners();
```

---

## `removeExtensionStateListener(IExtensionStateListener listener)`
This method is used to remove an extension state listener that has been registered by the extension. **Note:** you must
pass the object returned from `registerExtensionStateListener()` instead of the JavaScript object if you are trying to
remove a JavaScript-based extension state listener. 

**Parameters:**

*  `listener` - The extension state listener to be removed.

**Example:**
```javascript
var listener = burpCallbacks.registerExtensionStateListener(function() { 
  alert('Extension Unloaded!');
});

burpCallbacks.removeExtensionStateListener(listener);
```

---

## `registerHttpListener(Object listener)`
This method is used to register a listener which will be notified of requests and responses made by any Burp tool.
Extensions can perform custom analysis or modification of these messages by registering an HTTP listener.

**Parameters:**

*  `listener` - An object created by the extension that implements the [IHttpListener](https://portswigger.net/burp/extender/api/burp/IHttpListener.html) interface or a lambda function that has the same prototype as the [IHttpListener.processHttpMessage()](https://portswigger.net/burp/extender/api/burp/IHttpListener.html#processHttpMessage(int,%20boolean,%20burp.IHttpRequestResponse)).


**Returns:**
The instance of `burp.IHttpListener` that was registered.

**Example:**

```javascript
burpCallbacks.registerHttpListener(function(toolFlag, isRequest, messageInfo) {
  alert('Processing message from ' + burpCallbacks.getToolName(toolFlag));
});
```

or:

```javascript
burpCallbacks.registerHttpListener({
  'processHttpMessage': function(toolFlag, isRequest, messageInfo) {
    alert('Processing message from ' + burpCallbacks.getToolName(toolFlag));
  }
});
```

---

## `getHttpListeners()`
This method is used to retrieve the HTTP listeners that are registered by the extension.

**Returns:**
A list of HTTP listeners that are currently registered by this extension.

**Example:**

```javascript
burpCallbacks.getHttpListeners();
```

---

## `removeHttpListener(IHttpListener listener)`
This method is used to remove an HTTP listener that has been registered by the extension. **Note:** you must
pass the object returned from `registerHttpListener()` instead of the JavaScript object if you are trying to
remove a JavaScript-based HTTP listener. 


**Parameters:**

*  `listener` - The HTTP listener to be removed.

**Example:**
```javascript
listener = burpCallbacks.registerHttpListener({
  'processHttpMessage': function(toolFlag, isRequest, messageInfo) {
    alert('Processing message from ' + burpCallbacks.getToolName(toolFlag));
  }
});
burpCallbacks.removeHttpListener(listener);
```

---

## `registerProxyListener(Object listener)`
This method is used to register a listener which will be notified of requests and responses being processed by
the Proxy tool. Extensions can perform custom analysis or modification of these messages, and control in-UI
message interception, by registering a proxy listener.


**Parameters:**

*  `listener` - An object created by the extension that implements the [IProxyListener](https://portswigger.net/burp/extender/api/burp/IProxyListener.html) interface or a lambda function that has the same prototype as the [IHttpListener.processProxyMessage()](https://portswigger.net/burp/extender/api/burp/IProxyListener.html#processProxyMessage(boolean,%20burp.IInterceptedProxyMessage)).

**Returns:**
The instance of `burp.IProxyListener` that was registered.

**Example:**

```javascript
burpCallbacks.registerProxyListener(function(isRequest, messageInfo) {
  alert('Is request? ' + isRequest);
});
```

or:

```javascript
burpCallbacks.registerProxyListener({
  'processProxyMessage': function(isRequest, messageInfo) {
    alert('Is request? ' + isRequest);
  }
});
```

---

## `getProxyListeners()`
This method is used to retrieve the Proxy listeners that are registered by the extension.

**Returns:**
A list of Proxy listeners that are currently registered by this extension.

**Example:**

```javascript
burpCallbacks.getProxyListeners();
```

---

## `removeProxyListener(IProxyListener listener)`
This method is used to remove a Proxy listener that has been registered by the extension. **Note:** you must
pass the object returned from `registerProxyListener()` instead of the JavaScript object if you are trying to
remove a JavaScript-based proxy listener. 

**Parameters:**

*  `listener` - The HTTP listener to be removed.

**Example:**
```javascript
listener = burpCallbacks.registerProxyListener(function(isRequest, messageInfo) {
  alert('Is request? ' + isRequest);
});
burpCallbacks.removeProxyListener(listener);
```

---

## `registerScannerListener(Object listener)`
This method is used to register a listener which will be notified of new issues that are reported by the Scanner
tool. Extensions can perform custom analysis or logging of Scanner issues by registering a Scanner listener.


**Parameters:**

*  `listener` - An object created by the extension that implements the [IScannerListener](https://portswigger.net/burp/extender/api/burp/IScannerListener.html) interface or a lambda function that has the same prototype as the [IScannerListener.newScanIssue()](https://portswigger.net/burp/extender/api/burp/IScannerListener.html#newScanIssue(burp.IScanIssue)).

**Returns:**
The instance of `burp.IScannerListener` that was registered.

**Example:**

```javascript
burpCallbacks.registerScannerListener(function(scanIssue) {
  alert('Got issue: ' + scanIssue.getIssueName());
});
```

or:

```javascript
burpCallbacks.registerScannerListener({
  'processProxyMessage': function(isRequest, messageInfo) {
    alert('Got issue: ' + scanIssue.getIssueName());
  }
});
```

---

## `getScannerListeners()`
This method is used to retrieve the Scanner listeners that are registered by the extension.

**Returns:**
A list of Scanner listeners that are currently registered by this extension.

**Example:**

```javascript
burpCallbacks.getScannerListeners();
```

---

## `removeScannerListener(IScannerListener listener)`
This method is used to remove a Scanner listener that has been registered by the extension. **Note:** you must
pass the object returned from `registerScannerListener()` instead of the JavaScript object if you are trying to
remove a JavaScript-based scanner listener. 

**Parameters:**

*  `listener` - The Scanner listener to be removed.

**Example:**
```javascript
listener = burpCallbacks.registerScannerListener(function(scanIssue) {
 alert('Got issue: ' + scanIssue.getIssueName());
});
burpCallbacks.removeScannerListener(listener);
```

---

## `registerScopeChangeListener(Object listener)`
This method is used to register a listener which will be notified of changes to Burp's suite-wide target scope.


**Parameters:**

*  `listener` - An object created by the extension that implements the [IScopeChangeListener](https://portswigger.net/burp/extender/api/burp/IScopeChangeListener.html) interface or a lambda function that has the same prototype as the [IScannerListener.scopeChanged()](https://portswigger.net/burp/extender/api/burp/IScopeChangeListener.html#scopeChanged()).

**Returns:**
The instance of `burp.IScannerListener` that was registered.

**Example:**

```javascript
burpCallbacks.registerScopeChangeListener(function() {
  alert('Scope changed!');
});
```

or:

```javascript
burpCallbacks.registerScopeChangeListener({
  'scopeChanged': function() {
     alert('Scope changed!');
  }
});
```

---

## `getScopeChangeListeners()`
This method is used to retrieve the scope change listeners that are registered by the extension.

**Returns:**
A list of scope change listeners that are currently registered by this extension.

**Example:**

```javascript
burpCallbacks.getScopeChangeListeners();
```

---

## `removeScopeChangeListener(IScannerListener listener)`
This method is used to remove a scope change listener that has been registered by the extension. **Note:** you must
pass the object returned from `registerScopeChangeListener()` instead of the JavaScript object if you are trying to
remove a JavaScript-based scope change listener. 

**Parameters:**

*  `listener` - The listener to be removed.

**Example:**
```javascript
listener = burpCallbacks.registerScopeChangeListener(function() {
 alert('Scope changed!');
});
burpCallbacks.removeScopeChangeListener(listener);
```

---

## `registerContextMenuFactory(Object factory)`
This method is used to register a factory for custom context menu items. When the user invokes a context menu
anywhere within Burp, the factory will be passed details of the invocation event, and asked to provide any
custom context menu items that should be shown.


**Parameters:**

*  `factory` - An object created by the extension that implements the [IContextMenuFactory](https://portswigger.net/burp/extender/api/burp/IContextMenuFactory.html) interface or a lambda function that has the same prototype as the [IContextMenuFactory.createMenuItems()](https://portswigger.net/burp/extender/api/burp/IContextMenuFactory.html#createMenuItems(burp.IContextMenuInvocation)).

**Returns:**
The instance of `burp.IContextMenuFactory` that was registered.

**Example:**

```javascript
burpCallbacks.registerContextMenuFactory(function(invocation) {
  alert('Context menu was invoked from ' + burpCallbacks.getToolName(invocation.getToolFlag()));
});
```

or:

```javascript
burpCallbacks.registerContextMenuFactory({
  'createMenuItems': function(invocation) {
     alert('Context menu was invoked from ' + burpCallbacks.getToolName(invocation.getToolFlag()));
  }
});
```

---

## `getContextMenuFactories()`
This method is used to retrieve the context menu factories that are registered by the extension.

**Returns:**
A list of context menu factories that are currently registered by this extension.

**Example:**

```javascript
burpCallbacks.getContextMenuFactories();
```

---

## `removeContextMenuFactory(IContextMenuFactory factory)`
This method is used to remove a context menu factory that has been registered by the extension. **Note:** you must
pass the object returned from `registerContextMenuFactory()` instead of the JavaScript object if you are trying to
remove a JavaScript-based context menu factory. 

**Parameters:**

*  `factory` - The context menu factory to be removed.

**Example:**
```javascript
factory = burpCallbacks.registerContextMenuFactory(function(invocation) {
  alert('Context menu was invoked from ' + burpCallbacks.getToolName(invocation.getToolFlag()));
});
burpCallbacks.removeContextMenuFactory(factory);
```

---

## `registerMessageEditorTabFactory(Object factory)`
This method is used to register a factory for custom message editor tabs. For each message editor that already
exists, or is subsequently created, within Burp, the factory will be asked to provide a new instance of an
`burp.IMessageEditorTab` object, which can provide custom rendering or editing of HTTP messages. **Note:** there is
a small difference between the interface provided by BurpSuite for `IMessageEditorTabFactory` and the interface
of the JavaScript-based `IMessageEditorTabFactory`. An extra `textEditor` parameter is passed to the `createNewInstance()`
which contains an instance of `ITextEditor`. This is done to avoid deadlocks due to interweaving call sequences between
the JavaFX and Swing event loops. 


**Parameters:**

*  `factory` - An object created by the extension that implements a variant of the [IMessageEditorTabFactory](https://portswigger.net/burp/extender/api/burp/IMessageEditorTabFactory.html) interface or a lambda function that has a variant of the prototype defined by the [IMessageEditorTabFactory.createNewInstance()](https://portswigger.net/burp/extender/api/burp/IMessageEditorTabFactory.html#createNewInstance(burp.IMessageEditorController,%20boolean)) with an extra `textEditor` parameter passed to `createNewInstance()`. See examples for nuances.

**Returns:**
The instance of `burp.IMessageEditorTabFactory` that was registered.

**Example:**

```javascript
burpCallbacks.registerMessageEditorTabFactory(function(controller, editable, textEditor) {
  alert('Created controller=' + controller + ', editable=' + editable + ', textEditor=' + textEditor);
});
```

or:

```javascript
burpCallbacks.registerMessageEditorTabFactory({
  'createNewInstance': function(controller, editable, textEditor) {
     alert('Created controller=' + controller + ', editable=' + editable + ', textEditor=' + textEditor);
  }
});
```

---

## `getMessageEditorTabFactories()`
This method is used to retrieve the message editor tab factories that are registered by the extension.

**Returns:**
A list of message editor tab factories that are currently registered by this extension.

**Example:**

```javascript
burpCallbacks.getMessageEditorTabFactories();
```

---

## `removeMessageEditorTabFactory(IMessageEditorTabFactory factory)`
This method is used to remove a message editor tab factory that has been registered by the extension. **Note:** you must
pass the object returned from `registerContextMenuFactory()` instead of the JavaScript object if you are trying to
remove a JavaScript-based message editor tab factory. 

**Parameters:**

*  `factory` - The message editor tab factory to be removed.

**Example:**
```javascript
factory = burpCallbacks.registerMessageEditorTabFactory(function(controller, editable, textEditor) {
  alert('Created controller=' + controller + ', editable=' + editable + ', textEditor=' + textEditor);
});
burpCallbacks.removeMessageEditorTabFactory(factory);
```

---

## `registerScannerInsertionPointProvider(Object provider)`
This method is used to register a provider of Scanner insertion points. For each base request that is actively
scanned, Burp will ask the provider to provide any custom scanner insertion points that are appropriate for the
request.

**Parameters:**

*  `provider` - An object created by the extension that implements the [IScannerInsertionPointProvider](https://portswigger.net/burp/extender/api/burp/IScannerInsertionPointProvider.html) interface or a lambda function that has the same prototype as the [IScannerInsertionPointProvider.getInsertionPoints()](https://portswigger.net/burp/extender/api/burp/IScannerInsertionPointProvider.html#getInsertionPoints(burp.IHttpRequestResponse)).

**Returns:**
The instance of `burp.IScannerInsertionPointProvider` that was registered.

**Example:**

```javascript
burpCallbacks.registerScannerInsertionPointProvider(function(baseRequestResponse) {
  baseRequestResponse.setComment('BurpKit rules!');
});
```

or:

```javascript
burpCallbacks.registerScannerInsertionPointProvider({
  'getInsertionPoints': function(baseRequestResponse) {
     baseRequestResponse.setComment('BurpKit rules!');
  }
});
```

---

## `getScannerInsertionPointProviders()`
This method is used to retrieve the Scanner insertion point providers that are registered by the extension.

**Returns:**
A list of Scanner insertion point providers that are currently registered by this extension.

**Example:**

```javascript
burpCallbacks.getContextMenuFactories();
```

---

## `removeScannerInsertionPointProvider(IScannerInsertionPointProvider provider)`
 **Note:** you must
pass the object returned from `registerScannerInsertionPointProvider()` instead of the JavaScript object if you are trying to
remove a JavaScript-based scope change listener. 

**Parameters:**

*  `provider` - The scanner insertion point provider to be removed.

**Example:**
```javascript
provider = burpCallbacks.registerScannerInsertionPointProvider(function(baseRequestResponse) {
  baseRequestResponse.setComment('BurpKit rules!');
});
burpCallbacks.removeScannerInsertionPointProvider(factory);
```

---

## `registerScannerCheck(Object check)`
This method is used to register a custom Scanner check. When performing scanning, Burp will ask the check to
perform active or passive scanning on the base request, and report any Scanner issues that are identified.

**Parameters:**

*  `check` - An object created by the extension that implements the [IScannerCheck](https://portswigger.net/burp/extender/api/burp/IScannerCheck.html) interface.

**Returns:**
The instance of `burp.IScannerCheck` that was registered.

**Example:**

```javascript
burpCallbacks.registerScannerCheck({
  'doPassiveScan': function(baseRequestResponse, newIssue) {
    // do passive scan logic
  },
  'doActiveScan': function(baseRequestResponse, insertionPoint) {
    // do active scan logic
  },
  'consolidateDuplicateIssues(existingIssue, newIssue) {
    // do comparison
    return 0;
  }
});
```

---

## `getScannerChecks()`
This method is used to retrieve the Scanner checks that are registered by the extension.

**Returns:**
A list of Scanner checks that are currently registered by this extension.

**Example:**

```javascript
burpCallbacks.getScannerChecks();
```

---

## `removeScannerCheck(IScannerCheck check)`
This method is used to remove a Scanner check that has been registered by the extension. **Note:** you must
pass the object returned from `registerScannerCheck()` instead of the JavaScript object if you are trying to
remove a JavaScript-based scanner check. 

**Parameters:**

*  `check` - The scanner check to be removed.

**Example:**
```javascript
check = burpCallbacks.registerScannerCheck({
  'doPassiveScan': function(baseRequestResponse, newIssue) {
    // do passive scan logic
  },
  'doActiveScan': function(baseRequestResponse, insertionPoint) {
    // do active scan logic
  },
  'consolidateDuplicateIssues(existingIssue, newIssue) {
    // do comparison
    return 0;
  }
});
burpCallbacks.removeScannerCheck(check);
```

---

## `registerIntruderPayloadGeneratorFactory(Object factory)`
This method is used to register a factory for Intruder payloads. Each registered factory will be available within
the Intruder UI for the user to select as the payload source for an attack. When this is selected, the factory
will be asked to provide a new instance of an `burp.IIntruderPayloadGenerator` object, which will
be used to generate payloads for the attack.

**Parameters:**

*  `factory` - An object created by the extension that implements the [IIntruderPayloadGeneratorFactory](https://portswigger.net/burp/extender/api/burp/IIntruderPayloadGeneratorFactory.html) interface.

**Returns:**
The instance of `burp.IIntruderPayloadGeneratorFactory` that was registered.

**Example:**

```javascript
burpCallbacks.registerIntruderPayloadGeneratorFactory({
    'createNewInstance': function(attack) {
        return new MyIntruderPayloadGenerator(attack); // your IIntruderPayloadGenerator object
    },
    'getGeneratorName': function() {
        return 'foo';
    }
});
```

---

## `getIntruderPayloadGeneratorFactories()`
This method is used to retrieve the Intruder payload generator factories that are registered by the extension.

**Returns:**
A list of Intruder payload generator factories that are currently registered by this extension.

**Example:**

```javascript
burpCallbacks.getIntruderPayloadGeneratorFactories();
```

---

## `removeIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory factory)`
This method is used to remove an Intruder payload generator factory that has been registered by the extension. **Note:** you must
pass the object returned from `registerIntruderPayloadGeneratorFactory()` instead of the JavaScript object if you are trying to
remove a JavaScript-based intruder payload generator factory. 

**Parameters:**

*  `factory` - The intruder payload generator factory to be removed.

**Example:**
```javascript
burpCallbacks.registerIntruderPayloadGeneratorFactory({
    'createNewInstance': function(attack) {
        return new MyIntruderPayloadGenerator(attack);
    },
    'getGeneratorName': function() {
        return 'foo';
    }
});
burpCallbacks.removeContextMenuFactory(factory);
```

---

## `registerIntruderPayloadProcessor(Object factory)`
This method is used to register a custom Intruder payload processor. Each registered processor will be available
within the Intruder UI for the user to select as the action for a payload processing rule.

**Parameters:**

*  `processor` - An object created by the extension that implements the [IIntruderPayloadProcessor](https://portswigger.net/burp/extender/api/burp/IIntruderPayloadProcessor.html) interface.

**Returns:**
The instance of `burp.IIntruderPayloadProcessor` that was registered.

**Example:**

```javascript
burpCallbacks.registerIntruderPayloadProcessor({
  'getProcessorName': function() {
     return 'BurpKit Processor';
  },
  'processPayload': function(currentPayload, originalPayload, baseValue) {
     // change something
     return modifiedBytes;
  }
});
```

---

## `getIntruderPayloadProcessors()`
This method is used to retrieve the Intruder payload processors that are registered by the extension.

**Returns:**
A list of Intruder payload processors that are currently registered by this extension.

**Example:**

```javascript
burpCallbacks.getIntruderPayloadProcessors();
```

---

## `removeIntruderPayloadProcessor(IContextMenuFactory factory)`
This method is used to remove an Intruder payload processor that has been registered by the extension. **Note:** you must
pass the object returned from `registerIntruderPayloadProcessor()` instead of the JavaScript object if you are trying to
remove a JavaScript-based intruder payload processor. 

**Parameters:**

*  `processor` - The intruder payload processor to be removed.

**Example:**
```javascript
processor = burpCallbacks.registerIntruderPayloadProcessor({
  'getProcessorName': function() {
     return 'BurpKit Processor';
  },
  'processPayload': function(currentPayload, originalPayload, baseValue) {
     // change something
     return modifiedBytes;
  }
});
burpCallbacks.removeIntruderPayloadProcessor(processor);
```

---

## `registerSessionHandlingAction(Object action)`
This method is used to register a custom session handling action. Each registered action will be available within
the session handling rule UI for the user to select as a rule action. Users can choose to invoke an action
directly in its own right, or following execution of a macro.

**Parameters:**

*  `action` - An object created by the extension that implements the [ISessionHandlingAction](https://portswigger.net/burp/extender/api/burp/ISessionHandlingAction.html) interface.

**Returns:**
The instance of `burp.ISessionHandlingAction` that was registered.

**Example:**

```javascript
burpCallbacks.registerSessionHandlingAction({
  'getActionName': function() {
     return 'BurpKit Action';
  },
  'performAction': function(currentRequest, macroItems) {
     // do something here
  }
});
```

---

## `getSessionHandlingActions()`
This method is used to retrieve the session handling actions that are registered by the extension.

**Returns:**
This method is used to retrieve the session handling actions that are registered by the extension.

**Example:**

```javascript
burpCallbacks.getSessionHandlingActions();
```

---

## `removeSessionHandlingAction(ISessionHandlingAction action)`
This method is used to remove a session handling action that has been registered by the extension. **Note:** you must
pass the object returned from `registerSessionHandlingAction()` instead of the JavaScript object if you are trying to
remove a JavaScript-based session handling action. 

**Parameters:**

*  `action` - The extension session handling action to be removed.

**Example:**
```javascript
action = burpCallbacks.registerSessionHandlingAction({
  'getActionName': function() {
     return 'BurpKit Action';
  },
  'performAction': function(currentRequest, macroItems) {
     // do something here
  }
});
burpCallbacks.removeSessionHandlingAction(action);
```

---

## `unloadExtension()`
This method is used to unload the extension from Burp Suite. If called, `BurpKit` will be unloaded.

**Example:**
```javascript
burpCallbacks.unloadExtension();
```

---

## `addSuiteTab(Object tab)`
This method is used to add a custom tab to the main Burp Suite window. 

**Parameters:**

*  `tab` - An object created by the extension that implements the [ITab](https://portswigger.net/burp/extender/api/burp/ITab.html) interface.

**Returns:**
The instance of `burp.ITab` that was created.

**Example:**
```javascript
burpCallbacks.addTab({
    'getTabCaption': function() {
        return 'foo';
    },
    'getUiComponent': function() {
        return new MyUiComponent();
    }
});
```

---

## `removeSuiteTab(ITab tab)`
This method is used to remove a previously-added tab from the main Burp Suite window. **Note:** you must
pass the object returned from `addSuiteTab()` instead of the JavaScript object if you are trying to
remove a JavaScript-based tab. 

**Parameters:**

*  `tab` - An object created by the extension that implements the [ITab](https://portswigger.net/burp/extender/api/burp/ITab.html) interface.

**Returns:**
The instance of `burp.ITab` that was created.

**Example:**
```javascript
burpCallbacks.addTab({
    'getTabCaption': function() {
        return 'foo';
    },
    'getUiComponent': function() {
        return new MyUiComponent();
    }
});
```

---

## `customizeUiComponent(Component component)`
This method is used to customize UI components in line with Burp's UI style, including font size, colors, table
line spacing, etc. The action is performed recursively on any child components of the passed-in component.

**Parameters:**

*  `component` - The UI component to be customized.

**Example:**
```javascript
burpCallbacks.customizeUiComponent(component);
```

---

## `createMessageEditor(Object controller, boolean editable, JSObject callback)`
This method is used to create a new instance of Burp's HTTP message editor, for the extension to use in its own
UI.

**Parameters:**

*  `controller` - An object created by the extension that implements the [IMessageEditorController](https://portswigger.net/burp/extender/api/burp/IMessageEditorController.html)  interface. This parameter is optional and may be `null`. If it is provided, then the message editor will query the controller when required to obtain details about the currently displayed message, including the `IHttpService` for the message, and the associated request or response message. If a controller is not provided, then the message editor will not support context menu actions, such as sending requests to other Burp tools.
*  `editable` - Indicates whether the editor created should be editable, or used only for message viewing.
*  `callback` - A JavaScript callback function that will be called once the `IMessageEditor` instance is created. The instance of `IMessageEditor` will be passed to the callback function as the first parameter.

**Example:**
```javascript
burpCallbacks.createMessageEditor(
    controller, 
    true,
    function(editor) {
        alert('Created an editor!');
    }
);
```

---

## `getCommandLineArguments()`
This method returns the command line arguments that were passed to Burp on startup.

**Returns:**
The command line arguments that were passed to Burp on startup.

**Example:**
```javascript
burpCallbacks.getCommandLineArguments();
```

---

## `saveExtensionSetting(String name, String value)`
This method is used to save configuration settings for the extension in a persistent way that survives reloads of
the extension and of Burp Suite. Saved settings can be retrieved using the method `loadExtensionSetting()`.

**Parameters:**

*  `name` - The name of the setting.
*  `value` - The value of the setting. If this value is `null` then any existing setting with the specified name will be removed.

**Example:**
```javascript
burpCallbacks.saveExtensionSetting('foo', 'bar');
```

---

## `loadExtensionSetting(String name)`
This method is used to load configuration settings for the extension that were saved using the method `saveExtensionSetting()`.

**Parameters:**

*  `name` - The name of the setting.

**Returns:**
The value of the setting, or `null` if no value is set.

**Example:**
```javascript
burpCallbacks.saveExtensionSetting('foo'); // returns 'bar'
```

---

## `createTextEditor()`
This method is used to create a new instance of Burp's plain text editor, for the extension to use in its own UI.

**Returns**:
An instance of `burp.ITextEditor`.

**Example:**
```javascript
burpCallbacks.createTextEditor();
```

---

# TODO: add rest of `burpCallbacks` API