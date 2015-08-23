## `httpGetBytes(String url)`
Makes an HTTP GET request for the given URL void of the same-origin policy.

**Parameters:**

*  `url` - the URL to fetch content from.

**Returns:**
A Java `byte[]` containing the HTTP response.

**Example:**
```javascript
var responseBytes = burpKit.httpGetBytes('http://www.google.com');
```

---

## `httpGetString(String url)`
Makes an HTTP GET request for the given URL void of the same-origin policy.

**Parameters:**

*  `url` - the URL to fetch content from.

**Returns:**
A string containing the HTTP response.

**Example:**
```javascript
var responseStr = burpKit.httpGetString('http://www.google.com');
```

---

## `require(String url)`
Executes the contents of the JavaScript script file located at the given URL in the context of the current DOM. 

**Parameters:**

*  `url` - the URL to fetch the JavaScript script contents from.

**Example:**
```javascript
burpKit.require('https://code.jquery.com/jquery-2.1.4.js');
```

---

## `requireLib(String library)`
Injects the library identified by the `library` parameter into the current DOM. See the parameters description for a list
of valid libraries that come pre-packaged with BurpKit. The library is usually contained within a `window.<libname>` object, 
with exception to the jQuery library which is directly injected into the DOM.

**Parameters:**

*  `library` - the name of the library you'd like to inject. Valid values are `'csvlib'`, `'httplib'`, `'beautifylib'`, `'iplib'`, `'rotlib'`, `'structlib'`, `'jquery'`, and `'cryptolib'`. 

**Example:**
```javascript
burpKit.require('csvlib'); // Can be accessed using window.csvlib
burpKit.require('httplib'); // Can be accessed using window.httplib
```

---

## `saveFileDialog(String title)`
Opens a file save dialog with the specified title, allowing the user to choose where a file is to be saved.

**Parameters:**

*  `title` - the title of the save file dialog window. 

**Returns:**
The full path of the file to save contents to.

**Example:**
```javascript
var csvFileName = burpKit.saveFileDialog('Where should we save your CSV?');
```

---

## `openFileDialog(String title)`
Opens a file open dialog with the specified title, allowing the user to choose a file to open.

**Parameters:**

*  `title` - the title of the open file dialog window. 

**Returns:**
The full path of the file to open.

**Example:**
```javascript
var csvFileName = burpKit.openFileDialog('Where is your CSV?');
```

---

## `openMultipleDialog(String title)`
Just like the `fileOpenDialog()` but allows multiple file selections.

**Parameters:**

*  `title` - the title of the multiple open file dialog window. 

**Returns:**
An array of full path file names.

**Example:**
```javascript
var csvFileNames = burpKit.openMultipleDialog('Where are your CSVs?');
```

---

## `writeToFile(String file, String data)`
Writes the contents of `data` to the file name specified in `file`. The file is opened and closed every time this method
is called. If the file exists already, the contents of the existing file will be replaced with the contents of `data`.

**Parameters:**

*  `file` - the file path to write to.
*  `data` - the data to write to file.

**Example:**
```javascript
var fileName = burpKit.saveFileDialog('Save location...');
burpKit.writeToFile(fileName, 'foo');
```

---

## `appendToFile(String file, String data)`
Appends the contents of `data` to the file name specified in `file`. The file is opened and closed every time this method
is called.

**Parameters:**

*  `file` - the file path to write to.
*  `data` - the data to append to file.

**Example:**
```javascript
var fileName = burpKit.saveFileDialog('Save location...');
burpKit.writeToFile(fileName, 'foo');
burpKit.appendToFile(fileName, 'bar');
```

---

## `readFromFile(String file)`
The contents of the file specified by `file` are slurped into a string and returned. The file is opened and closed every
time this method is invoked.

**Parameters:**

*  `file` - the file name to read data from.

**Example:**
```javascript
var fileName = burpKit.openFileDialog('Select file...');
alert(burpKit.readFromFile(fileName));
```

---

## `loginPrompt(JSObject callback)`
Prompts the user from login credentials. This can be used to write scripts that are driven by the BurpKit `document.onload`
event loop.

**Parameters:**

*  `callback` - a callback function that accepts two parameters: `username` and `password`.

**Example:**
```javascript
burpKit.loginPrompt(function(username, password) {
    // Here we are leveraging jQuery to select, fill, and submit the login form.
    // Luckily Twitter has already included jQuery as part of the page. 
    var form = $('form.signin')[0];
    $('[name="session[username_or_email]"]', form)[0].value = username;
    $('[name="session[password]"]', form)[0].value = password;
    locals.put('loopCount', loopCount + 1);
    form.submit();
});
```

---

## `prompt(String question)`
Prompts the user for input. Similar to `window.prompt()`.

**Parameters:**

*  `question` - the question that the user needs to provide input for.

**Returns:**
A string containing the answer.

**Example:**
```javascript
var identity = burpKit.prompt("Who are you?");
```

---

## `homeDirectory()`
Returns the user's home directory. Useful for default file save locations.

**Returns:**
A string containing the user's home directory path.

**Example:**
```javascript
var homeDir = burpKit.homeDirectory();
```

---

## `pathJoin(String first, JSObject pathList)`
Joins the paths in `first` and `pathList` using the native OS separator character.

**Parameters:**

*  `first` - the first part of the path (i.e. '/Users')
*  `pathList` - an array of paths to join (i.e. ['foo', 'bar'])

**Returns:**
A string with the joined path.

**Example:**
```javascript
burpKit.pathJoin('/Users', ['foo', 'bar']); // returns '/Users/foo/bar'
```

---

## `locals()` and `globals()`
Returns a global Java `Map` object that persists between `document.onload` events. `locals()` returns a map that is
global to the current BurpKit tab, whereas `globals()` returns a map that is global to all of the BurpKit tabs. Values
and names are strings, therefore the result of `toString()` will be stored where non-string objects are encountered.
Persistence of complex objects can be achieved using a variety of string-based formats including XML, JSON, etc.

**Returns:**
A Java `Map` object that persists between page loads.

**Example:**
```javascript
// Run in console.
burpKit.locals().set('foo', 'bar');
document.location = 'http://www.google.ca';
burpKit.locals().get('foo') // returns 'bar'
```

--- 

## `createJMenuItem(String caption, JSObject handler)`
Creates a `JMenuItem` component that is useful for creating context menu items for BurpSuite plugins. 

**Parameters:**

*  `caption` - the label of the menu item
*  `handler` - an object that adheres to the `ActionListener` interface or a lambda function that accepts an `ActionEvent` argument.

**Example:**
```javascript
burpKit.createJMenuItem('Test', function(event) { alert('clicked!'); });
});
```

or 

```javascript
burpKit.createJMenuItem('Test', {
    'actionPerformed': function(event) { alert('clicked!'); }
});
```