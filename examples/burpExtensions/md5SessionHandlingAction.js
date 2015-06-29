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
 * Created by ndouba on 15-06-28.
 */

burpKit.requireLib('cryptolib');

if ('sessionHandlingAction' in window && sessionHandlingAction != null) {
    alert('Removing old session handling action.');
    burpCallbacks.removeSessionHandlingAction(sessionHandlingAction);
}

alert('Registering new session handling action!');
var sessionHandlingAction = burpCallbacks.registerSessionHandlingAction({
    'helpers': burpCallbacks.getHelpers(),
    'removePreviousHashHeader': function(headers) {
        for (var i = headers.size() - 1; i >= 0; i--) {
            var header = headers.get(i);
            if (header.indexOf('Hash:') == 0) headers.remove(header);
        }
    },
    'getActionName': function() {
        return 'Add MD5 Header';
    },
    'performAction': function(currentRequest, macroItems) {
        var requestBytes = currentRequest.getRequest();
        var requestInfo = this.helpers.analyzeRequest(requestBytes);
        var headers = requestInfo.getHeaders();

        // Remove the previous HTTP 'Hash' header.
        this.removePreviousHashHeader(headers);

        // Get the HTTP body to calculate it's MD5 hash sum
        var msgBody = this.helpers.bytesToString(requestBytes).substring(requestInfo.getBodyOffset());

        // Add the 'Hash' HTTP header
        headers.add('Hash: ' + cryptolib.MD5(msgBody).toString());

        // modify the current request to include the hash header
        currentRequest.setRequest(this.helpers.buildHttpMessage(headers, msgBody));

    }
});


