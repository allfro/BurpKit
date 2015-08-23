The `burpKit` object provides language extensions to the JavaScript engine. These extensions provide developers with
the ability to write and read files to and from the filesystem, inject arbitrary JavaScript libraries into the DOM, or
perform HTTP requests regardless of same-origin policies. `burpKit` is automatically injected into the DOM after every
`document.onload` event. The following example is a small snippet that demonstrates some of the API features that are part
of the `burpKit` object:

```javascript
var fileName = burpKit.saveFileDialog("Where would you like to save the file contents?");

if (fileName != null) {
    burpKit.requireLib('csvlib'); // inject a CSV library into the DOM
    
    var csvData = [['Name', 'Value']]; // CSV title row
    data.push(['foo', 'bar']); // arbitrary CSV data row
    
    // Write results to CSV file
    csvlib.stringify(
        data, 
        function(err, output) {
            burpKit.writeToFile(fileName, output); 
        }
    );
}
```

The following subsections details the methods that are part of the `burpKit` object.