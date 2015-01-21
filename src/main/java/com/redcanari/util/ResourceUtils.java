package com.redcanari.util;

import burp.BurpExtender;

import java.io.IOException;
import java.io.InputStream;

/**
 * Created by ndouba on 15-01-01.
 */
public class ResourceUtils {

    public static String getResourceContentsAsString(String filename) {
        InputStream inputStream = ResourceUtils.class.getResourceAsStream(filename);
        try {
            byte buffer[] = new byte[inputStream.available()];
            inputStream.read(buffer);
            return new String(buffer);
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }
}
