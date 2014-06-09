package com.redcanari.util;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * Created by ndouba on 2014-06-02.
 */
public class DigestUtils {

    public static String toDigest(byte[] content) {
        String md5String = null;
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5String = new BigInteger(1, md5.digest(content)).toString(16);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return md5String;
    }
}
