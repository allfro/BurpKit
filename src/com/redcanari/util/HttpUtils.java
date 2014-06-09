package com.redcanari.util;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;


/**
 * Created by ndouba on 2014-06-02.
 */
public class HttpUtils {


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
            List<String> normalizedParameters = new ArrayList<String>();
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
}
