/*
 * BurpKit - WebKit-based penetration testing plugin for BurpSuite
 * Copyright (C) 2015  Red Canari, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * The following code snippet demonstrates how to create a plain text
 * editing tab for BurpSuite message editors. Unlike the traditional
 * interface for `IMessageEditorTabFactory`, the JavaScript interface
 * accepts one extra parameter - `editorFactory`. `editorFactory` is an
 * instance of the BurpSuite `ITextEditor` which gets created using
 * the BurpSuite `createTextEditor()` callback. This is passed into
 * our tab object to avoid deadlocks between the FX and Swing threads.
 * Currently, you CANNOT create GUI controls in JavaScript since this
 * will eventually lead to deadlock issues.
 */

// Our constructor for our `IMessageEditorTab` accepts 2 parameters:
// `editable`, and `textEditor`.
function Base64InputTab(editable, textEditor) {
    this.currentMessage = null;
    this.editable = editable;
    this.helpers = burpCallbacks.getHelpers();
    this.type = 0;
    this.txtInput = textEditor;
    this.txtInput.setEditable(editable);
}

// Our `Base64InputTab` follows exactly the same interface as that
// defined by the `IMessageEditorTab` tab. Below you will find all
// the methods expected by BurpSuite's API. The following tab is a
// JavaScript port of the `IMessageEditorTab` example found on
// PortSwigger's website, which decodes the value of the HTTP
// Base64 encoded `data` parameter in a separate tab and re-encodes
// any changes made in that tab back into Base64.
Base64InputTab.prototype = {
    'getTabCaption': function() {
        return "Serialized Input";
    },
    'getUiComponent': function() {
        return this.txtInput.getComponent();
    },
    'isEnabled': function(content, isRequest) {
        return (isRequest && null != this.helpers.getRequestParameter(content, "data"));
    },
    'setMessage': function(content, isRequest) {
        if (content == null)
        {
            this.txtInput.setText(null);
            this.txtInput.setEditable(false);
        }
        else
        {
            var parameter = this.helpers.getRequestParameter(content, "data");
            this.type = parameter.getType();

            this.txtInput.setText(this.helpers.base64Decode(this.helpers.urlDecode(parameter.getValue())));
            this.txtInput.setEditable(true);
        }

        this.currentMessage = content;
    },
    'getMessage': function() {
        if (this.txtInput.isTextModified())
        {
            var text = this.txtInput.getText();
            var input = this.helpers.urlEncode(this.helpers.base64Encode(text));
            return this.helpers.updateParameter(this.currentMessage, this.helpers.buildParameter("data", input, this.type));
        }
        return this.currentMessage;
    },
    'isModified': function() {
        return this.txtInput.isTextModified();
    },
    'getSelectedData': function() {
        return this.txtInput.getSelectedData();
    }
};

// Remove our old message editor tab factory if it was previous defined.
if ('textEditorFactory' in window) {
    alert('Unregistering old text editor tab factory');
    burpCallbacks.removeMessageEditorTabFactory(textEditorFactory);
}

alert('Registering text editor tab factory!');

// Register our new message editor tab factory. Notice the discrepancy
// between the `IMessageEditorTabFactory` interface defined in BurpSuite's
// API and here. To avoid deadlocks, BurpKit passes an extra `editorFactory`
// parameter to the `createNewInstance` callback. This is a factory class
// that can be used to retrieve an instance of `ITextEditor` using the
// `editFactory.getTextEditor()` method or an instance of `IMessageEditor`
// using the `editFactory.getMessageEditor()` method.
textEditorFactory = burpCallbacks.registerMessageEditorTabFactory(function(controller, editable, editorFactory) {
    return new Base64InputTab(editable, editorFactory.getTextEditor());
});