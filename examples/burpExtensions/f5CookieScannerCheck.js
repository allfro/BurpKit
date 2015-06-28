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
 * The following example demonstrates how to write a BurpSuite scanner
 * check. This example is based on code found at the SecureIdeas blog:
 * http://blog.secureideas.com/2013/08/burp-extension-for-f5-cookie-detection.html.
 * This scanner check will attempt to detect the existence of 'BIGipServer'
 * persistence cookie using passive scanning techniques. If this cookie
 * exists, the IP address and port of the backend server is decoded, and
 * a scan issues is reported back to BurpSuite.
 */


// We include `structlib` which provides functionality similar to the
// python `struct.pack()` and `struct.unpack()` functions. We need this
// to flip integers between little and big endianness.
burpKit.requireLib('structlib');

// We include `iplib` to check whether or not an IP address is a local/
// private address using the `isPrivate()` function.
burpKit.requireLib('iplib');


// This function compresses uncompressed IPv6 addresses like so:
// '20010112000000000000000000000030' -> '[2001:112::30]'
function simplifyIPv6Address(address) {
    return '[' + address.match(/(.{4})/g).join(':').replace(/(:0000)+/, ':').replace(/:0{1,3}/g, ':') + ']';
}


// Convert integer from network to host short endianness.
function ntohs(value) {
    return structlib.unpack(">H", structlib.pack("<H", [parseInt(value)]))[0];
}


// Decodes simple BIGIP persistence cookies of the format '1677787402.36895.0000'
function decodeSimpleF5Cookie(value) {
    var values = value.split('.');

    var host = structlib.pack("<I", [parseInt(values[0])]);
    var port = structlib.unpack(">H", structlib.pack("<H", [parseInt(values[1])]))[0];

    var ipAddress = host[0] + '.' + host[1] + '.' + host[2] + '.' + host[3];

    return {'address' : ipAddress, 'port' : port, 'isPrivate' : iplib.isPrivate(ipAddress)};
}


// Decodes complex BIGIP persistence cookies of the formats:
// 'rd5o00000000000000000000ffffc0000201o80' or
// 'vi20010112000000000000000000000030.20480' or
// 'rd3o20010112000000000000000000000030o80'
function decodeComplexF5Cookie(value) {
    var result = {};
    var values = null;
    if (value.indexOf('rd') == 0) {
        if (value.indexOf('00000000000000000000ffff') != -1) {
            values = value.split('00000000000000000000ffff')[1].split('o');
            result.address = iplib.fromLong(parseInt(values[0], 16));
            result.port = parseInt(values[1]);
        } else {
            values = value.split('o');
            result.address = simplifyIPv6Address(values[1]);
            result.port = parseInt(values[2]);
        }
    } else if (value.indexOf('vi') == 0) {
        values = value.substring(2).split('.');
        result.address = simplifyIPv6Address(values[0]);
        result.port = ntohs(parseInt(values[1]));
    }
    result.isPrivate = iplib.isPrivate(result.address);
    return result;
}


// Decodes BIGIP persistence cookies using the following spec:
// https://support.f5.com/kb/en-us/solutions/public/6000/900/sol6917.html
function decodeF5Cookie(value) {
    alert('Starting decode...');
    var result = ((value.match(/\./g) || []).length == 2)?decodeSimpleF5Cookie(value):decodeComplexF5Cookie(value);
    alert('F5 decoded cookie: ' + result.address + ':' + result.port);
    return result;
}


// Check if this scannerCheck was previously registered and deregister.
if ('scannerCheck' in window && scannerCheck != null) {
    alert('Removing old scanner check.');
    burpCallbacks.removeScannerCheck(scannerCheck);
}


// Register our passive scanner check.
alert('Registering new scanner check!');
var scannerCheck = burpCallbacks.registerScannerCheck({
    'doPassiveScan': function(baseRequestResponse) {
        var helpers = burpCallbacks.getHelpers();
        var analyzedResponse = helpers.analyzeResponse(baseRequestResponse.getResponse());
        var cookies = analyzedResponse.getCookies();
        var issues = [];

        // Loop through each cookie checking for the presence
        // of the BIGIP cookie and create a new issue.
        for (var i = 0; i < cookies.size(); i++) {
            var cookie = cookies.get(i);
            var cookieName = cookie.getName();
            var cookieValue = cookie.getValue();

            // Make sure the cookie name starts with BIGipServer
            if (cookieName.toLowerCase().indexOf("bigipserver") == 0) {
                issues.push(new F5PassiveScanIssue(
                    baseRequestResponse,
                    cookieName,
                    cookieValue,
                    decodeF5Cookie(cookieValue)
                ));
            }
        }

        // Return our issues array if we have found F5 cookies
        if (issues.length > 0) {
            alert('Found ' + issues.length + ' F5 cookie issue(s).');
            return issues;
        }
        alert('No F5 cookie issues identified.');
        return null;

    },
    'doActiveScan': function(baseRequestResponse, insertionPoint) {
        return null;
    },
    'consolidateDuplicateIssues': function(existingIssue, newIssue) {
        // If the issue details are the same, then we have the same issue and
        // we can consolidate them. Otherwise, both issues should remain.
        return (existingIssue.getIssueDetail() == newIssue.getIssueDetail())?1:0;
    }
});


// This is our `IScanIssue` class which will be used to hold scan
// issue information. We follow the same interface as `IScanIssue`.
function F5PassiveScanIssue(baseRequestResponse, cookieName,
                            cookieValue, decodedCookie) {
    this.httpService = baseRequestResponse.getHttpService();
    this.messages = [baseRequestResponse];
    this.url = baseRequestResponse.getUrl();
    this.cookieName = cookieName;
    this.cookieValue = cookieValue;
    this.address = decodedCookie.address;
    this.port = decodedCookie.port;
    this.severity = (decodedCookie.isPrivate)?'Medium':'Low';
}

F5PassiveScanIssue.prototype = {
    'getUrl': function() {
        return this.url;
    },
    'getIssueName': function() {
        return "Encoded IP Address Discovered in F5 Cookie Value";
    },
    'getIssueType': function() {
        return burpCallbacks.INS_PARAM_COOKIE;
    },
    'getSeverity': function() {
        return this.severity;
    },
    'getConfidence': function() {
        return "Certain";
    },
    'getIssueBackground': function() {
        return "<p>These cookies are purposed for load balancing and if not properly protected, " +
            "will reveal IP addresses and ports of internal servers. This information provides " +
            "an attacker with additional insight into the environment and could be used to craft " +
            "better targeted attacks.</p><p>See the Secure Ideas blog article <b>Decoding F5 Cookie</b> " +
            "article: <a href='#'>http://blog.secureideas.com/2013/02/decoding-f5-cookie.html</a></p>";
    },
    'getRemediationBackground': function() {
        return "<p>Additional information can be found in the F5 Knowledge Base article: " +
            "<b>SOL7784: Configuring BIG-IP cookie encryption (9.x):</b> " +
            "<a href='#'>http://support.f5.com/kb/en-us/solutions/public/7000/700/sol7784.html?sr=14607726</a></p>";
    },
    'getIssueDetail': function() {
        var msg = "<p>The URL <b>" + this.url.toString() + "</b> sets the F5 load balancer cookie <b>" +
            this.cookieName + "</b>, which is used to maintain a connection to a specific web server.</p><p>The " +
            "cookie value contains the F5 encoded IP address and port information:  <b>" +
            this.cookieValue + "</b>.</p><p>This decodes to the value: <b>" + this.address + ":" +
            this.port + "</b></p>";
        if (this.issueSeverity != "Low") {
            msg += "<p>This is considered a <b>" + this.severity + "</b> severity vulnerability because the " +
                "cookie exposes the internal IP address and port number used by the web server behind the " +
                "load balancer.</p>";
        }
        return msg;
    },
    'getRemediationDetail': function() {
        return "<p>Consult the F5 documentation for instructions on how to encrypt HTTP cookies " +
            "before sending them to the client system. Two common methods are to configure cookie " +
            "encryption using the HTTP profile or by using an iRule.</p>";
    },
    'getHttpMessages': function() {
        return this.messages;
    },
    'getHttpService': function() {
        return this.httpService;
    },
    'getHost': function() {
        return this.address;
    },
    'getPort': function() {
        return this.port;
    },
    'getProtocol': function() {
        return this.url.getProtocol();
    }
};