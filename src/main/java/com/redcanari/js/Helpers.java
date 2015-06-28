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

import com.google.gson.Gson;
import javafx.scene.web.WebEngine;
import netscape.javascript.JSObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by ndouba on 14-12-08.
 */
public class Helpers {

    private static SecureRandom random = new SecureRandom();

    private static String getRandomString() {
        return "__temp_" + new BigInteger(130, random).toString(32);
    }

    public static Map<String, Object> toJavaMap(WebEngine webEngine, JSObject jsObject) {
        String temporaryIdentifier = getRandomString();
        JSObject window = (JSObject)webEngine.executeScript("window");
        window.setMember(temporaryIdentifier, jsObject);
        Map<String, Object> map = new HashMap<>();
        return new Gson().fromJson((String) webEngine.executeScript("JSON.stringify(" + temporaryIdentifier + ")"), Map.class);
    }


    public static JSObject toJSMap(WebEngine webEngine, Map<String, String> map) throws IOException {
        JSObject o = (JSObject) webEngine.executeScript(new Gson().toJson(map).toString());
        return (JSObject) o.getSlot(0);
    }

    public static <T> JSObject toJSArray(WebEngine webEngine, T[] array) {
        JSObject jsObject = (JSObject) webEngine.executeScript("new Array()");

        for (int i = 0; i < array.length; i++)
            jsObject.setSlot(i, array[i]);

        return jsObject;
    }

    public static JSObject toJSArray(WebEngine webEngine, List list) {
        JSObject jsObject = (JSObject) webEngine.executeScript("new Array()");

        if (list == null || list.isEmpty())
            return jsObject;

        Object[] array = list.toArray();

        for (int i = 0; i < array.length; i++)
            jsObject.setSlot(i, array[i]);

        return jsObject;
    }

    public static <T> JSObject toTwoDimensionalJSArray(WebEngine webEngine, T[][] twoDimensionalArray) {
        JSObject jsObject = (JSObject) webEngine.executeScript("new Array()");

        for (int i = 0; i < twoDimensionalArray.length; i++) {
            JSObject jsObject2 = (JSObject) webEngine.executeScript("new Array()");
            for (int j = 0; j < twoDimensionalArray[i].length; j++)
                jsObject2.setSlot(j, twoDimensionalArray[i][j]);
            jsObject.setSlot(i, jsObject2);
        }

        return jsObject;
    }

    private static int getJSArrayLength(JSObject jsObject) {
        return (int)jsObject.getMember("length");
    }

    public static <T> T[] toJavaArray(JSObject jsObject, Class cls) {
        int length = getJSArrayLength(jsObject);
        T[] array = (T[]) ((Object[]) Array.newInstance(cls, length));

        for (int i = 0; i < length; i++)
            array[i] = (T) jsObject.getSlot(i);

        return array;
    }

    public static <T> List<T> toJavaList(JSObject jsObject) {
        ArrayList<T> listArray = new ArrayList<T>();
        int length = getJSArrayLength(jsObject);

        for (int i = 0; i < length; i++)
            listArray.add((T) jsObject.getSlot(i));

        return listArray;
    }

    public static <T> List<T> toJavaProxyList(JSObject jsObject, Class cls) {
        ArrayList<T> listArray = new ArrayList<T>();
        int length = getJSArrayLength(jsObject);

        for (int i = 0; i < length; i++)
            listArray.add(Helpers.<T>wrapInterface(jsObject.getSlot(i), cls));

        return listArray;
    }

    public static <T> List<T[]> toTwoDimenionalJavaListArray(JSObject jsObject) {
        ArrayList<T[]> arrayList = new ArrayList<>();
        int length = getJSArrayLength(jsObject);

        for (int i = 0; i < length; i++) {
            List<T> subArrayList = Helpers.<T>toJavaList((JSObject) jsObject.getSlot(i));
            arrayList.add((T[]) subArrayList.toArray());
        }

        return arrayList;
    }

    public static List<int[]> toTwoDimensionalJavaListIntArray(JSObject jsObject) {
        ArrayList<int[]> arrayList = new ArrayList<>();
        int length = getJSArrayLength(jsObject);

        for (int i = 0; i < length; i++)
            arrayList.add(toPrimitiveIntArray((JSObject) jsObject.getSlot(i)));

        return arrayList;
    }

    public static int[] toPrimitiveIntArray(JSObject jsObject) {
        int length = getJSArrayLength(jsObject);
        int[] array = new int[length];

        for (int i = 0; i < length; i++)
            array[i] = (int) jsObject.getSlot(i);

        return array;
    }


    public static byte[] toPrimitiveArray(Byte[] array) {
        byte[] destination = new byte[array.length];

        for (int i = 0; i < array.length; i++)
            destination[i] = array[i];

        return destination;
    }

    public static byte[] toPrimitiveByteArray(Integer[] array) {
        byte[] destination = new byte[array.length];

        for (int i = 0; i < array.length; i++)
            destination[i] = array[i].byteValue();

        return destination;
    }

    public static int[] toPrimitiveArray(Integer[] array) {
        int[] destination = new int[array.length];

        for (int i = 0; i < array.length; i++)
            destination[i] = array[i];

        return destination;
    }

    /**
     * A private API for wrapping BurpSuite interfaces around instances of {@link netscape.javascript.JSObject} using
     * proxy classes.
     *
     * This function returns a proxy class that wraps around the original {@link netscape.javascript.JSObject} to
     * enable calls between the BurpSuite framework and the JavaFX JavaScript engine. It achieves this by wrapping
     * The proxy classes inherit from the BurpSuite framework interfaces.
     *
     * Example:
     *
     * {@code IScanIssue scanIssue = this.<IScanIssue>wrapInterface(scanIssue, ScanIssueJSProxy.class);}
     *
     *
     * @param object        The {@link netscape.javascript.JSObject} object to be wrapped.
     * @param proxyClass    One of the proxy classes from {@link com.redcanari.js.proxies}
     * @param <T>           One of the proxy classes from {@link com.redcanari.js.proxies}
     * @return  an instance of a proxy class that resides in {@link com.redcanari.js.proxies}.
     */
    public static <T> T wrapInterface(Object object, Class<?> proxyClass) {
        if (object instanceof JSObject) {
            try {
                object = proxyClass.getDeclaredConstructor(JSObject.class).newInstance(object);
            } catch (InstantiationException | IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
                e.printStackTrace();
            }
        }
        return (T) object;
    }

    public static JSObject toJSArray(WebEngine webEngine, byte[] bytes) {
        JSObject jsObject = (JSObject) webEngine.executeScript("new Array()");

        if (bytes == null || bytes.length == 0)
            return jsObject;

        for (int i = 0; i < bytes.length; i++)
            jsObject.setSlot(i, bytes[i]);

        return jsObject;
    }

    public static String convertStreamToString(java.io.InputStream inputStream) {
        java.util.Scanner s = new java.util.Scanner(inputStream).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

    public static byte[] convertStreamToBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[16384];

        while (inputStream.read(data) != -1)
            buffer.write(data);

        return buffer.toByteArray();
    }

    /**
     * A private API used to convert regular {@link JSObject} or {@link String} objects
     * into {@code byte[]}.
     *
     * @param data the object that will be converted into bytes.
     * @return  the data in {@code byte[]}.
     */
    public static byte[] getBytes(Object data) {
        if (data instanceof String)
            data = ((String) data).getBytes();
        else if (data instanceof JSObject)
            data = toPrimitiveByteArray(Helpers.<Integer>toJavaArray((JSObject) data, Integer.class));
        return (byte[]) data;
    }
}
