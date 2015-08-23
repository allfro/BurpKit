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

## `sendToRepeater(String host, int port, boolean useHttps, Object request, String tabCaption)`
This method can be used to send an HTTP request to the Burp Repeater tool. The request will be displayed in the
user interface, but will not be issued until the user initiates this action. 

**Parameters:**

*  `host` - The hostname of the remote HTTP server.
*  `port` - The port of the remote HTTP server.
*  `useHttps` - Flags whether the protocol is HTTPS or HTTP.
*  `request` - A Java `byte[]` or `String` containing the full HTTP request.
*  `tabCaption` - An optional caption which will appear on the Repeater tab containing the request. If this value is `null` then a default tab index will be displayed.

**Example:**
```javascript
burpCallbacks.sendToRepeater(
    'google.com',
    80,
    true,
    'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n',
    'Google'
);
```

---

## `sendUrlToRepeater(String url, String tabCaption)`
Does the same thing as `sendToRepeater()` with less effort for HTTP GET requests. This method will automatically build 
an HTTP GET request by simply processing the URL and inserting cookie information from the WebKit/JavaFX cookie jar. 

**Parameters:**

*  `url` - The URL of the request to send to the repeater.
*  `tabCaption` - An optional caption which will appear on the Repeater tab containing the request. If this value is `null` then a default tab index will be displayed.

**Example:**
```javascript
burpCallbacks.sendUrlToRepeater(
    'http://www.google.com',
    'Google'
);
```

---

## `sendToIntruder(String host, int port, boolean useHttps, Object request)`
This method can be used to send an HTTP request to the Burp Intruder tool. The request will be displayed in the
user interface, and markers for attack payloads will be placed into default locations within the request. 

**Parameters:**

*  `host` - The hostname of the remote HTTP server.
*  `port` - The port of the remote HTTP server.
*  `useHttps` - Flags whether the protocol is HTTPS or HTTP.
*  `request` - A Java `byte[]` or `String` containing the full HTTP request.

**Example:**
```javascript
burpCallbacks.sendToIntruder(
    'google.com',
    80,
    true,
    'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'
);
```

---

## `sendUrlToIntruder(String url)`
Does the same thing as `sendToIntruder()` with less effort for HTTP GET requests. This method will automatically build 
an HTTP GET request by simply processing the URL and inserting cookie information from the WebKit/JavaFX cookie jar.

**Parameters:**

*  `url` - The URL of the request to send to the intruder.

**Example:**
```javascript
burpCallbacks.sendUrlToIntruder(
    'http://www.google.com',
);
```

---

## `sendToIntruder2(String host, int port, boolean useHttps, Object request, Object payloadPositionOffsets)`
This method can be used to send an HTTP request to the Burp Intruder tool. The request will be displayed in the
user interface, and markers for attack payloads will be placed into the specified locations within the request.

**Parameters:**

*  `host` - The hostname of the remote HTTP server.
*  `port` - The port of the remote HTTP server.
*  `useHttps` - Flags whether the protocol is HTTPS or HTTP.
*  `request` - A Java `byte[]` or `String` containing the full HTTP request.
*  `payloadPositionOffsets` - A list of index pairs representing the payload positions to be used. Each item the list must be an `int[2]` array containing the start and end offset for the payload position.

**Example:**
```javascript
burpCallbacks.sendToIntruder2(
    'google.com',
    80,
    true,
    'GET /?q=bar HTTP/1.1\r\nHost: www.google.com\r\n\r\n',
    [[8,11]] // position from beginning to end of 'bar' in request
);
```

---

## `sendToComparer(Object data)`
This method can be used to send data to the Comparer tool.

**Parameters:**

*  `data` - A Java `byte[]` or `String` containing the data to be compared.

**Example:**
```javascript
burpCallbacks.sendToComparer('foo');
```

---

## `sendToSpider(String url)`
This method can be used to send a seed URL to the Burp Spider tool. If the URL is not within the current Spider
scope, the user will be asked if they wish to add the URL to the scope. If the Spider is not currently running,
it will be started. The seed URL will be requested, and the Spider will process the application's response in
the normal way.

**Parameters:**

*  `url` - The new seed URL to begin spidering from.

**Example:**
```javascript
burpCallbacks.sendToSpider('http://www.google.com');
```

---

## `doActiveScan(String host, int port, boolean useHttps, Object request, JSObject callback)`
This method can be used to send an HTTP request to the Burp Scanner tool to perform an active vulnerability scan.
If the request is not within the current active scanning scope, the user will be asked if they wish to proceed
with the scan. 

**Parameters:**

*  `host` - The hostname of the remote HTTP server.
*  `port` - The port of the remote HTTP server.
*  `useHttps` - Flags whether the protocol is HTTPS or HTTP.
*  `request` - A Java `byte[]` or `String` containing the full HTTP request.
*  `callback` -  A JavaScript callback function that gets called with an instance of `burp.IScanQueueItem` as its first argument once successfully created.

**Example:**
```javascript
queue = [];
burpCallbacks.doActiveScan(
    'google.com',
    80,
    true,
    'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'
    function(scanQueueItem) { queue.push(scanQueueItem); }
);
```

---

## `doActiveScan2(String host, int port, boolean useHttps, Object request, Object payloadPositionOffsets, JSObject callback)`
This method can be used to send an HTTP request to the Burp Scanner tool to perform an active vulnerability scan. If the 
request is not within the current active scanning scope, the user will be asked if they wish to proceed with the scan. 
Markers for attack payloads will be placed into the specified locations within the request.

**Parameters:**

*  `host` - The hostname of the remote HTTP server.
*  `port` - The port of the remote HTTP server.
*  `useHttps` - Flags whether the protocol is HTTPS or HTTP.
*  `request` - A Java `byte[]` or `String` containing the full HTTP request.
*  `payloadPositionOffsets` - A list of index pairs representing the payload positions to be used. Each item the list must be an `int[2]` array containing the start and end offset for the payload position.
*  `callback` - A JavaScript callback function that gets called with an instance of `burp.IScanQueueItem` as its first argument once successfully created.

**Example:**
```javascript
queue = [];
burpCallbacks.doActiveScan2(
    'google.com',
    80,
    true,
    'GET /?q=bar HTTP/1.1\r\nHost: www.google.com\r\n\r\n',
    [[8,11]] // position from beginning to end of 'bar' in request,
    function(scanQueueItem) { queue.push(scanQueueItem); }
);
```

---

## `doActiveUrlScan(String url, JSObject callback)`
Does the same thing as `doActiveScan()` with less effort for HTTP GET requests. This method will automatically build 
an HTTP GET request by simply processing the URL and inserting cookie information from the WebKit/JavaFX cookie jar.

**Parameters:**

*  `url` - The URL of the request to send to the scanner.
*  `callback` -  A JavaScript callback function that gets called with an instance of `burp.IScanQueueItem` as its first argument once successfully created.

**Example:**
```javascript
queue = [];
burpCallbacks.doActiveUrlScan(
    'http://www.google.com',
    function(scanQueueItem) { queue.push(scanQueueItem); }
);
```

---

## `doPassiveScan(String host, int port, boolean useHttps, Object request, Object response)`
This method can be used to send an HTTP request to the Burp Scanner tool to perform a passive vulnerability scan.

**Parameters:**

*  `host` - The hostname of the remote HTTP server.
*  `port` - The port of the remote HTTP server.
*  `useHttps` - Flags whether the protocol is HTTPS or HTTP.
*  `request` - A Java `byte[]` or `String` containing the full HTTP request.
*  `response` -  A Java `byte[]` or `String` containing the full HTTP response.

**Example:**
```javascript
burpCallbacks.doPassiveScan(
    'google.com',
    80,
    true,
    'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'
    'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
);
```

---

## `makeHttpRequest(IHttpService httpService, Object request)`
This method can be used to issue HTTP requests and retrieve their responses.

**Parameters:**

*  `httpService` - The HTTP service to which the request should be sent.
*  `request` - A Java `byte[]` or `String` containing the full HTTP request.

**Returns:**
An instance of `burp.IHttpRequestResponse`.

**Example:**
```javascript
var helpers = burpCallbacks.getHelpers();
var requestResponse = burpCallbacks.makeHttpRequest(
    helpers.buildHttpService('google.com', 80, true), // SSL request to google.com
    'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'
);
```

--- 

## `makeUrlHttpRequest(String url)`
A shortcut method to performing HTTP GET requests by providing only the URL. This method will automatically build 
an HTTP GET request by simply processing the URL and inserting cookie information from the WebKit/JavaFX cookie jar.

**Parameters:**

*  `url` - The destination URL to make a request for.

**Returns:**
An instance of `burp.IHttpRequestResponse`.

**Example:**
```javascript
var requestResponse = burpCallbacks.makeUrlHttpRequest(
    'http://www.google.com'
);
```

## `makeHttpRequest2(String host, int port, boolean useHttps, Object request)`
This method can be used to issue HTTP requests and retrieve their responses.

**Parameters:**

*  `host` - The hostname of the remote HTTP server.
*  `port` - The port of the remote HTTP server.
*  `useHttps` - Flags whether the protocol is HTTPS or HTTP.
*  `request` - A Java `byte[]` or `String` containing the full HTTP request.

**Returns:**
A `byte[]` containing the response data.

**Example:**
```javascript
var response = burpCallbacks.makeHttpRequest2(
    'www.google.com',
    80,
    true,
    'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'
);
```

--- 


## `makeUrlHttpRequest2(String url)`
This method can be used to issue HTTP requests and retrieve their responses. This method will automatically build 
an HTTP GET request by simply processing the URL and inserting cookie information from the WebKit/JavaFX cookie jar.


**Parameters:**

*  `url` - The destination URL to make a request for.

**Returns:**
A `byte[]` containing the response data.

**Example:**
```javascript
var response = burpCallbacks.makeUrlHttpRequest2(
    'http://www.google.com'
);
```

--- 

## `isInScope(String url)`
This method can be used to query whether a specified URL is within the current Suite-wide scope.

**Parameters:**

*  `url` - The URL to check whether it is in the Suite-wide scope.

**Returns:**
`true` if in scope, otherwise `false`

**Example:**
```javascript
burpCallbacks.isInScope('http://www.google.com');
```

--- 


## `includeInScope(String url)`
This method can be used to include the specified URL in the Suite-wide scope.

**Parameters:**

*  `url` - The URL to include in the Suite-wide scope.

**Example:**
```javascript
burpCallbacks.includeInScope('http://www.google.com');
```

--- 

## `excludeFromScope(String url)`
This method can be used to exclude the specified URL from the Suite-wide scope.

**Parameters:**

*  `url` - The URL to exclude from the Suite-wide scope.

**Example:**
```javascript
burpCallbacks.excludeFromScope('http://www.google.com');
```

--- 

## `issueAlert(String message)`
This method can be used to exclude the specified URL from the Suite-wide scope.

**Parameters:**

*  `message` - The alert message to display.

**Example:**
```javascript
burpCallbacks.issueAlert('This is awesome!');
```

--- 

## `getProxyHistory()`
This method returns details of all items in the Proxy history.

**Returns:**
The contents of the Proxy history.

**Example:**
```javascript
var proxyHistory = burpCallbacks.getProxyHistory();
```

--- 

## `getSiteMap(String urlPrefix)`
This method returns details of items in the site map.

**Parameters:**

*  `urlPrefix` - This parameter can be used to specify a URL prefix, in order to extract a specific subset of the site map. The method performs a simple case-sensitive text match, returning all site map items whose URL begins with the specified prefix. If this parameter is null, the entire site map is returned.

**Returns:**
Details of items in the site map.

**Example:**
```javascript
var siteMap = burpCallbacks.getSiteMap('google.com');
```

--- 

## `getScanIssues(String urlPrefix)`
This method returns all of the current scan issues for URLs matching the specified literal prefix.

**Parameters:**

*  `urlPrefix` - This parameter can be used to specify a URL prefix, in order to extract a specific subset of scan issues. The method performs a simple case-sensitive text match, returning all scan issues whose URL begins with the specified prefix. If this parameter is null, all issues are returned.

**Returns:**
Details of items in the scan issues.

**Example:**
```javascript
var scanIssues = burpCallbacks.getScanIssues('google.com');
```

--- 

## `generateScanReport(String format, Object issues, String file)`
This method is used to generate a report for the specified Scanner issues. The report format can be specified.
For all other reporting options, the default settings that appear in the reporting UI wizard are used.

**Parameters:**

*  `format` - The format to be used in the report. Accepted values are `'HTML'` and `'XML'`.
*  `issues` - The Scanner issues to be reported.
*  `file` - The file to which the report will be saved.

**Example:**
```javascript
burpCallbacks.generateScanReport(
    'HTML', 
    burpCallbacks.getScanIssues('google.com'), 
    'myReport.html'
);
```

--- 

## `getCookieJarContents()`
This method is used to retrieve the contents of Burp's session handling cookie jar. Extensions that provide an
`burp.ISessionHandlingAction` can query and update the cookie jar in order to handle unusual session handling mechanisms.

**Returns:**
A list of `burp.ICookie` objects representing the contents of Burp's session handling cookie jar.

**Example:**
```javascript
var cookies = burpCallbacks.getCookieJarContents();
```

--- 

## `updateCookieJar(Object cookie)`
This method is used to update the contents of Burp's session handling cookie jar. Extensions that provide an
`burp.ISessionHandlingAction` can query and update the cookie jar in order to handle unusual session handling mechanisms.

**Parameters:**

*  `cookie` - An object that adheres to the interface of [ICookie](https://portswigger.net/burp/extender/api/burp/ICookie.html), containing details of the cookie to be updated. If the cookie jar already contains a cookie that matches the specified domain and name, then that cookie will be updated with the new value and expiration, unless the new value is null, in which case the cookie will be removed. If the cookie jar does not already contain a cookie that matches the specified domain and name, then the cookie will be added.

**Returns:**
The instance of `burp.ICookie` that was used to modify the cookie jar.

**Example:**
```javascript
var cookies = burpCallbacks.updateCookieJar({
    'getDomain': function() {return 'google.com';},
    'getExpiration': function() {return null;},
    'getName': function() {return 'MyCookie';},
    'getValue': function() {return 'MyValue';},
});
```

---

## `addToSiteMap(Object item)`
This method can be used to add an item to Burp's site map with the specified request/response details. This will
overwrite the details of any existing matching item in the site map.
     
**Parameters:**

*  `item` - An object that adheres to the interface of [IHttpRequestResponse](https://portswigger.net/burp/extender/api/burp/IHttpRequestResponse.html) and contains the details to add to the sitemap.

**Example:**
```javascript
var helpers = burpCallbacks.getHelpers();
var cookies = burpCallbacks.addToSiteMap({
    'request': helpers.stringToBytes('GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'),
    'response': helpers.stringToBytes('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'),
    'highlight': 'orange',
    'httpService': helpers.buildHttpService('google.com', 80, true),
    'comment': 'BurpKit rules!',
    'getComment': function() {return this.comment;},
    'getHighlight': function() {return this.highlight;},
    'getHttpService': function() {return this.httpService;},
    'getRequest': function() {return this.request;},
    'getResponse': function() {return this.response;},
    'setComment': function(comment) {this.comment = comment;},
    'setHighlight': function(highlight) {this.highlight = highlight},    
    'setHttpService': function(httpService) {this.httpService = httpService},
    'setRequest': function(request) {this.request = request},
    'setResponse': function(response) {this.response = response},
});
``` 

---

## `restoreState(String file)`
This method can be used to restore Burp's state from a specified saved state file. This method blocks until the
restore operation is completed, and must not be called from the event dispatch thread.
     
**Parameters:**

*  `file` - The file name containing Burp's saved state.

**Example:**
```javascript
burpCallbacks.restoreState('/tmp/burp.state');
``` 

---

## `saveState(String file)`
This method can be used to save Burp's state to a specified file. This method blocks until the save operation is
completed, and must not be called from the event dispatch thread.
     
**Parameters:**

*  `file` - The file name to save Burp's state in.

**Example:**
```javascript
burpCallbacks.saveState('/tmp/burp.state');
``` 

---

## `saveConfig()`
This method causes Burp to save all of its current configuration as a Map of name/value Strings.

**Returns:**
A Map of name/value Strings reflecting Burp's current configuration.

**Example:**
```javascript
var config = burpCallbacks.saveConfig();
config['foo'] = 'bar';
alert(config['foo']);
``` 

---

## `loadConfig(JSObject config)`
This method causes Burp to load a new configuration from the Map of name/value Strings provided. Any settings not
specified in the Map will be restored to their default values. To selectively update only some settings and leave
the rest unchanged, you should first call `saveConfig()` to obtain Burp's current configuration, modify the relevant
items in the Map, and then call `loadConfig()` with the same Map.
     
**Parameters:**

*  `config` - A map of name/value Strings to use as Burp's new configuration.

**Example:**
```javascript
var config = burpCallbacks.saveConfig();
config['foo'] = 'bar';
alert(config['foo']);
burpCallbacks.loadConfig(config);
``` 

---


## `setProxyInterceptionEnabled(boolean enabled)`
This method sets the master interception mode for Burp Proxy.
     
**Parameters:**

*  `enabled` - Indicates whether interception of Proxy messages should be enabled.

**Example:**
```javascript
burpCallbacks.setProxyInterceptionEnabled(false); // turn off interception
burpCallbacks.setProxyInterceptionEnabled(true); // turn on interception
``` 

---

## `getBurpVersion()`
This method retrieves information about the version of Burp in which the extension is running. It can be used by
extensions to dynamically adjust their behavior depending on the functionality and APIs supported by the current
version.

**Returns:**
An array of Strings comprised of: the product name (e.g. Burp Suite Professional), the major version (e.g. 1.5), the minor version (e.g. 03)

**Example:**
```javascript
burpCallbacks.getBurpVersion();
``` 

---

## `exitSuite(boolean promptUser)`
This method can be used to shut down Burp programmatically, with an optional prompt to the user. If the method
returns, the user canceled the shutdown prompt.
     
**Parameters:**

*  `promptUser` - Indicates whether to prompt the user to confirm the shutdown.

**Example:**
```javascript
burpCallbacks.exitSuite(true);
``` 

---

## `saveToTempFile(Object buffer)`
This method is used to create a temporary file on disk containing the provided data. Extensions can use temporary
files for long-term storage of runtime data, avoiding the need to retain that data in memory.

**Parameters:**

*  `buffer` - An object that adheres to the interface of [ITempFile](https://portswigger.net/burp/extender/api/burp/ITempFile.html), containing the data to be saved to a temporary file.

**Returns:**
The instance of `burp.ITempFile` that was used as a temporary file.

**Example:**
```javascript
var tempFile = burpCallbacks.saveToTempFile({
    'getBuffer': function() {return helpers.stringToBytes('foo data');},
    'delete': function() {} // deprecated do not use.
});
```

---

## `saveBuffersToTempFiles(IHttpRequestResponse httpRequestResponse)`
This method is used to save the request and response of an IHttpRequestResponse object to temporary files, so
that they are no longer held in memory. Extensions can used this method to convert `IHttpRequestResponse` objects
into a form suitable for long-term storage.

**Parameters:**

*  `httpRequestResponse` - The `IHttpRequestResponse` object whose request and response messages are to be saved to temporary files.

**Returns:**
An object that implements the `burp.IHttpRequestResponsePersisted` interface.

**Example:**
```javascript
var persistedRequestResponse = burpCallbacks.saveBuffersToTempFiles(requestResponse);
```

---

## `applyMarkers(IHttpRequestResponse httpRequestResponse, Object requestMarkers, Object responseMarkers)`
This method is used to apply markers to an HTTP request or response, at offsets into the message that are
relevant for some particular purpose. Markers are used in various situations, such as specifying Intruder payload
positions, Scanner insertion points, and highlights in Scanner issues.

**Parameters:**

*  `httpRequestResponse` - The `IHttpRequestResponse` object to which the markers should be applied.
*  `requestMarkers` - A list of index pairs representing the offsets of markers to be applied to the request message. Each item in the list must be an `int[2]` array containing the start and end offsets for the marker. The markers in the list should be in sequence and not overlapping. This parameter is optional and may be `null` if no request markers are required.
*  `responseMarkers` - A list of index pairs representing the offsets of markers to be applied to the response message. Each item in the list must be an `int[2]` array containing the start and end offsets for the marker. The markers in the list should be in sequence and not overlapping. This parameter is optional and may be `null` if no response markers are required.

**Returns:**
An object that implements the `burp.IHttpRequestResponseWithMarkers` interface.

**Example:**
```javascript
var markedRequestResponse = burpCallbacks.applyMarkers(requestResponse, [[8,2]], null);
```

---

## `getToolName(int toolFlag)`
This method is used to obtain the descriptive name for the Burp tool identified by the tool flag provided.

**Parameters:**

*  `toolFlag` - A flag identifying a Burp tool (`TOOL_PROXY`, `TOOL_SCANNER`, etc.). Tool flags are defined within the `burpCallbacks` object.

**Returns:**
The descriptive name for the specified tool.

**Example:**
```javascript
alert(burpCallbacks.getToolName(burpCallbacks.TOOL_PROXY));
```

---

## `addScanIssue(Object issue)`
This method is used to register a new Scanner issue. **Note:** Wherever possible, extensions should implement custom
Scanner checks using `IScannerCheck` and report issues via those checks, so as to integrate with Burp's user-driven
workflow, and ensure proper consolidation of duplicate reported issues. This method is only designed for tasks
outside of the normal testing workflow, such as importing results from other scanning tools.

**Parameters:**

*  `issue` - An object created by the extension that implements the [IScanIssue](https://portswigger.net/burp/extender/api/burp/IScanIssue.html) interface.

**Returns:**
The instance of `burp.IScanIssue` that was created.

**Example:**
```javascript
var scanIssue = burpCallbacks.addScanIssue({
    'getConfidence': function() { return 'Certain'; },
    'getHttpMessages': function() { return []; },
    'getHttpService': function() { return null; },
    'getIssueBackground': function() { return 'Background'; },
    'getIssueDetail': function() { return 'Detail'; },
    'getIssueName': function() { return 'Name'; },
    'getIssueType': function() { return 1; },
    'getRemediationBackground': function() { return 'Fix'; },
    'getRemediationDetail': function() { return 'Fix Detail'; },
    'getSeverity': function() { return 'High'; },
    'getUrl': function() { return 'http://www.google.com'; },
});
```