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

package com.redcanari.js.proxies;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import netscape.javascript.JSObject;

import java.net.URL;

/**
 * Created by ndouba on 15-05-16.
 */
public class HttpRequestResponseJSProxy extends JSProxy implements IHttpRequestResponse {

    public HttpRequestResponseJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public byte[] getRequest() {
        return call("getRequest");
    }

    @Override
    public void setRequest(byte[] bytes) {
        call("setRequest", bytes, null);
    }

    @Override
    public byte[] getResponse() {
        return call("getResponse");
    }

    @Override
    public void setResponse(byte[] bytes) {
        call("setResponse", bytes, null);
    }

    @Override
    public String getComment() {
        return call("getComment");
    }

    @Override
    public void setComment(String s) {
        call("setComment", s);
    }

    @Override
    public String getHighlight() {
        return call("getHighlight");
    }

    @Override
    public void setHighlight(String s) {
        call("setHighlight", s);
    }

    @Override
    public IHttpService getHttpService() {
        return call("getHttpService");
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        call("setHttpService", httpService);
    }

    @Override
    public String getHost() {
        return call("getHost");
    }

    @Override
    public int getPort() {
        return call("getPort");
    }

    @Override
    public String getProtocol() {
        return call("getProtocol");
    }

    @Override
    public void setHost(String s) {
        call("setHost", s);
    }

    @Override
    public void setPort(int i) {
        call("setPort", i);
    }

    @Override
    public void setProtocol(String s) {
        call("setProtocol", s);
    }

    @Override
    public URL getUrl() {
        return call("getUrl");
    }

    @Override
    public short getStatusCode() {
        return call("getShortCode");
    }
}
