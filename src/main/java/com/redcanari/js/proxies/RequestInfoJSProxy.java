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

import burp.IParameter;
import burp.IRequestInfo;
import com.redcanari.js.Helpers;
import netscape.javascript.JSObject;

import java.net.URL;
import java.util.List;

/**
 * @author Nadeem Douba
 * @version 1.0
 * @since 2015-05-17.
 */
public class RequestInfoJSProxy extends JSProxy implements IRequestInfo {

    public RequestInfoJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public String getMethod() {
        return call("getMethod");
    }

    @Override
    public URL getUrl() {
        return call("getUrl");
    }

    @Override
    public List<String> getHeaders() {
        return Helpers.toJavaList(call("getHeaders"));
    }

    @Override
    public List<IParameter> getParameters() {
        return Helpers.toJavaProxyList(call("getParameters"), ParameterJSProxy.class);
    }

    @Override
    public int getBodyOffset() {
        return call("getBodyOffset");
    }

    @Override
    public byte getContentType() {
        return call("getContentType");
    }
}
