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
 * The following example demonstrates how to use a context menu to add
 * a ROT13 encoder/decoder. When a user highlights a fragment of text
 * in a message editor, a menu item called "ROT13" will appear. If the
 * user clicks on this menu item, then the selected text is rotated.
 */

burpKit.requireLib("rotlib");

if ('contextMenuFactory' in window) {
    alert('Unregistering old context menu factory.');
    burpCallbacks.removeContextMenuFactory(contextMenuFactory);
}

alert('Registering new context menu factory!');
contextMenuFactory = burpCallbacks.registerContextMenuFactory(function(invocation){

    burpCallbacks.issueAlert(
        'Context menu factory invoked from ' +
        burpCallbacks.getToolName(invocation.getToolFlag())
    );

    if (invocation.getInvocationContext() == burpCallbacks.CONTEXT_MESSAGE_EDITOR_REQUEST) {
        return [
            // `burpKit.createJMenuItem()` is a factory function that is provided
            // to create a regular `JMenuItem`. The first argument is the label of
            // the menu item and the second is the event handler.
            burpKit.createJMenuItem(
                'ROT13',
                function(event) {
                    var helpers = burpCallbacks.getHelpers();

                    // Since the invocation context only applies to right clicks
                    // in message editors, we will only need the first request.
                    var messageInfo = invocation.getSelectedMessages()[0];
                    var request = messageInfo.getRequest();

                    // Get and check the selection bounds for that message. If
                    // the end matches the beginning then we know nothing has
                    // been selected and we just exit the handler.
                    var selectionBounds = invocation.getSelectionBounds();

                    if (selectionBounds[0] == selectionBounds[1])
                        return;

                    // Convert the request to a string to make things easier
                    var requestString = helpers.bytesToString(request);

                    // Get the snippet of text from the beginning of the request
                    // to the beginning of the selection bounds.
                    var beginSnip = requestString.substring(0, selectionBounds[0]);

                    // Get the snippet of text from the end of the selection bounds
                    // to the end of the request.
                    var endSnip = requestString.substring(selectionBounds[1], requestString.length);

                    // Get the selected text to encode.
                    var toEncode = requestString.substring(selectionBounds[0], selectionBounds[1]);

                    // Now encode the selected text and reconstruct the request.
                    var result = beginSnip + rotlib.rot(toEncode, 13) + endSnip;

                    // Finally, set the new message contents.
                    messageInfo.setRequest(helpers.stringToBytes(result));
                }
            )
        ];
    }

    // Don't return any context menus if this is not invoked from a message request editor.
    return [];
});