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

package com.redcanari.js;

import burp.*;
import com.redcanari.js.wrappers.RequestInfoWrapper;
import javafx.scene.web.WebEngine;
import netscape.javascript.JSObject;

import java.net.MalformedURLException;
import java.util.List;

/**
 * @author Nadeem Douba
 * @version 1.0
 * @since 2015-05-17.
 */
public class ExtensionHelpersBridge extends JavaScriptBridge {

    public ExtensionHelpersBridge(WebEngine webEngine, IBurpExtenderCallbacks burpExtenderCallbacks) {
        super(webEngine, burpExtenderCallbacks);
    }
    
    
    public IRequestInfo analyzeRequest(Object request) {
        IRequestInfo requestInfo = null;
        if (request instanceof byte[])
            requestInfo = helpers.analyzeRequest((byte[]) request);
        else if (request instanceof String)
            requestInfo = helpers.analyzeRequest(Helpers.getBytes(request));
        else if (request instanceof IHttpRequestResponse)
            requestInfo = helpers.analyzeRequest((IHttpRequestResponse)request);
        return new RequestInfoWrapper(requestInfo);
    }

    
    public IRequestInfo analyzeRequest2(IHttpService httpService, Object request) {
        return new RequestInfoWrapper(helpers.analyzeRequest(httpService, Helpers.getBytes(request)));
    }

    
    public IResponseInfo analyzeResponse(Object response) {
        return helpers.analyzeResponse(Helpers.getBytes(response));
    }

    
    public IParameter getRequestParameter(Object request, String parameterName) {
        return helpers.getRequestParameter(Helpers.getBytes(request), parameterName);
    }

    
    public String urlDecode(String data) {
        return helpers.urlDecode(data);
    }

    
    public String urlEncode(String data) {
        return helpers.urlEncode(data);
    }

    
    public byte[] urlDecode2(Object data) {
        return helpers.urlDecode(Helpers.getBytes(data));
    }

    
    public byte[] urlEncode2(Object data) {
        return helpers.urlEncode(Helpers.getBytes(data));
    }

    
    public byte[] base64Decode(Object data) {
        return helpers.base64Decode(Helpers.getBytes(data));
    }


    public String base64Decode2(Object data) {
        return helpers.bytesToString(base64Decode(data));
    }

    
    public String base64Encode(Object data) {
        return helpers.base64Encode(Helpers.getBytes(data));
    }


    public byte[] stringToBytes(String data) {
        return helpers.stringToBytes(data);
    }

    
    public String bytesToString(byte[] data) {
        return helpers.bytesToString(data);
    }

    
    public int indexOf(Object data, Object pattern, boolean caseSensitive, int from, int to) {
        return helpers.indexOf(Helpers.getBytes(data), Helpers.getBytes(pattern), caseSensitive, from, to);
    }

    
    public byte[] buildHttpMessage(Object headers, Object body) {
        return helpers.buildHttpMessage(
                (headers instanceof JSObject)?Helpers.<String>toJavaList((JSObject)headers):(List<String>)headers,
                Helpers.getBytes(body)
        );
    }

    
    public byte[] buildHttpRequest(String url) throws MalformedURLException {
        return helpers.buildHttpRequest(getNormalizedURL(url));
    }

    
    public byte[] addParameter(Object request, IParameter parameter) {
        return helpers.addParameter(Helpers.getBytes(request), parameter);
    }

    
    public byte[] removeParameter(Object request, IParameter parameter) {
        return helpers.removeParameter(Helpers.getBytes(request), parameter);
    }

    
    public byte[] updateParameter(Object request, IParameter parameter) {
        return helpers.updateParameter(Helpers.getBytes(request), parameter);
    }

    
    public byte[] toggleRequestMethod(Object request) {
        return helpers.toggleRequestMethod(Helpers.getBytes(request));
    }

    
    public IHttpService buildHttpService(String host, int port, String protocol) {
        return helpers.buildHttpService(host, port, protocol);
    }

    
    public IHttpService buildHttpService2(String host, int port, boolean useHttps) {
        return helpers.buildHttpService(host, port, useHttps);
    }

    
    public IParameter buildParameter(String name, String value, int type) {
        return helpers.buildParameter(name, value, (byte)type);
    }

    
    public IScannerInsertionPoint makeScannerInsertionPoint(String insertionPointName, Object baseRequest, int from, int to) {
        return helpers.makeScannerInsertionPoint(insertionPointName, Helpers.getBytes(baseRequest), from, to);
    }

    public String toString() {
        return "[object ExtensionHelpers]";
    }
}
