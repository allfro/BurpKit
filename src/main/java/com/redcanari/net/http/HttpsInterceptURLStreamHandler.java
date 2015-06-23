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

package com.redcanari.net.http;

import sun.net.www.protocol.https.Handler;
import sun.net.www.protocol.https.HttpsURLConnectionImpl;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;

/**
* Created by ndouba on 2014-06-04.
*/
public class HttpsInterceptURLStreamHandler extends Handler {

//    @Override
//    protected URLConnection openConnection(URL url) throws IOException {
//        return openConnection(url, null);
//    }

    @Override
    protected URLConnection openConnection(URL url, Proxy proxy) throws IOException {
        return new InterceptedHttpsURLConnection(url, (HttpsURLConnectionImpl)super.openConnection(url, proxy));
    }
}
