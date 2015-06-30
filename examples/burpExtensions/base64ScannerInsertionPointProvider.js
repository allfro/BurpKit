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
if ('scannerProvider' in window && scannerProvider != null) {
    alert('Removing old scanner insertion point provider.');
    burpCallbacks.removeScannerInsertionPointProvider(scannerProvider);
}

var helpers = burpCallbacks.getHelpers();

alert('Registering new scanner insertion point provider!');
burpCallbacks.registerScannerInsertionPointProvider(function (baseRequestResponse) {
    var dataParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "data");
    if (dataParameter == null)
        return null;

    return [new Base64InsertionPoint(baseRequestResponse.getRequest(), dataParameter.getValue())];
});


function Base64InsertionPoint(baseRequest, dataParameter) {
    this.baseRequest = baseRequest;

    // URL- and base64-decode the data
    dataParameter = helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(dataParameter)));

    // parse the location of the input string within the decoded data
    var start = dataParameter.indexOf("input=") + 6;
    this.insertionPointPrefix = dataParameter.substring(0, start);
    var end = dataParameter.indexOf("&", start);
    if (end == -1)
        end = dataParameter.length;
    this.baseValue = dataParameter.substring(start, end);
    this.insertionPointSuffix = dataParameter.substring(end, dataParameter.length);
}

Base64InsertionPoint.prototype = {
    'getInsertionPointName': function () {
        return "Base64-wrapped input";
    },
    'getBaseValue': function() {
        return this.baseValue;
    },
    'buildRequest': function(payload) {
        var input = this.insertionPointPrefix + helpers.bytesToString(payload) + this.insertionPointSuffix;

        // Base64- and URL-encode the data
        input = helpers.urlEncode(helpers.base64Encode(input));

        // update the request with the new parameter value
        return helpers.updateParameter(this.baseRequest, helpers.buildParameter("data", input, burpCallbacks.PARAM_BODY));
    },
    'getPayloadOffsets': function(payload) {
        // since the payload is being inserted into a serialized data structure, there aren't any offsets
        // into the request where the payload literally appears
        return null;
    },
    'getInsertionPointType': function() {
        return burpCallbacks.INS_EXTENSION_PROVIDED;
    }
};