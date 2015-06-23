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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * @author  Nadeem Douba
 * @version 1.0
 * @since   2014-06-02.
 */
public class DigestUtils {

    /**
     * Returns the md5 message digest of byte array.
     *
     * @param content   the byte array that requires digesting
     * @return  the md5 digest of the byte array as a {@code java.lang.String}
     */
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
