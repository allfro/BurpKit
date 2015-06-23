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

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import javafx.scene.web.WebEngine;
import netscape.javascript.JSObject;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * @author Nadeem Douba
 * @version 1.0
 * @since 2015-05-17.
 */
public class JavaScriptBridge {


    protected final IExtensionHelpers helpers;
    protected final IBurpExtenderCallbacks burpExtenderCallbacks;
    protected final WebEngine webEngine;

    public JavaScriptBridge(WebEngine webEngine, IBurpExtenderCallbacks burpExtenderCallbacks) {
        this.burpExtenderCallbacks = burpExtenderCallbacks;
        this.helpers = burpExtenderCallbacks.getHelpers();
        this.webEngine = webEngine;
    }

    /**
     * A private API used to convert regular {@link netscape.javascript.JSObject} or {@link java.lang.String} objects
     * into {@code byte[]}.
     *
     * @param data the object that will be converted into bytes.
     * @return  the data in {@code byte[]}.
     */
    protected byte[] getBytes(Object data) {
        if (data instanceof String)
            data = ((String) data).getBytes();
        else if (data instanceof JSObject)
            data = Helpers.toPrimitiveByteArray(Helpers.<Integer>toJavaArray((JSObject) data, Integer.class));
        return (byte[]) data;
    }


    /**
     * A private API used to convert any URL string into a well-formed URL that includes scheme, port, and path/file
     * information.
     *
     * @param url   the URL to be normalized
     * @return  A normalized {@link java.net.URL} object.
     * @throws java.net.MalformedURLException
     */
    protected URL getNormalizedURL(String url) throws MalformedURLException {
        URL urlObject = new URL(url);

        String host = urlObject.getHost();

        boolean useHttps = isHttps(urlObject);

        int port = urlObject.getPort();
        if (port == -1)
            port = (useHttps)?443:80;

        String file = urlObject.getFile();
        if (file == null || file.isEmpty())
            file = "/";

        return new URL(urlObject.getProtocol(), host, port, file);
    }


    /**
     * Returns true if the URL has a scheme of {@value "https"}
     *
     * @param url the URL to check.
     * @return {@value true} if the URL's protocol is {@value "https"}, otherwise {@value false}
     */
    protected boolean isHttps(URL url) {
        return url.getProtocol().equals("https");
    }

}
