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

package com.redcanari.util;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;


/**
 * @author  Nadeem Douba
 * @version 1.0
 * @since   2014-06-02
 */
public class HttpUtils {

    /**
     * Returns a string containing a properly formed URL with port and scheme information.
     * @param url the {@link java.net.URL} that needs normalization.
     * @return a {@link java.lang.String} that contains a well-formed URL.
     */
    public static String normalizeUrl(URL url) {
        int port = url.getPort();
        String portString = "";
        String protocol = url.getProtocol().toLowerCase();
        String file = url.getFile();
        String query = url.getQuery();

        if (port == -1)
             port = (url.getProtocol().equals("https")) ? 443 : 80;
        if ((protocol.equals("http") && port != 80) || (protocol.equals("https") && port != 443))
             portString = ":" + port;

        if (query != null) {
            List<String> normalizedParameters = new ArrayList<>();
            for (String parameter : query.split("&")) {
                String[] nameValue = parameter.split("=", 2);

                try {
                    nameValue[0] = URLEncoder.encode(URLDecoder.decode(nameValue[0], "UTF-8"), "UTF-8");
                    if (nameValue.length != 2)
                        normalizedParameters.add(nameValue[0]);
                    else {
                        nameValue[1] = URLEncoder.encode(URLDecoder.decode(nameValue[1], "UTF-8"), "UTF-8");
                        normalizedParameters.add(nameValue[0] + "=" + nameValue[1]);
                    }
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }

            }
            file = file.replace(query, String.join("&", normalizedParameters));
        }

        return protocol + "://" + url.getHost().toLowerCase() + portString + file;
    }

    /**
     * Returns true if the URL string begins with the standard HTTP protocol schemes.
     *
     * @param url a string containing a URL string.
     * @return a boolean indicating whether the string starts with "http://" or "https://"
     */
    public static boolean isHttpURL(String url) {
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }

}
