package com.redcanari.js;

import burp.IHttpRequestResponse;
import com.oracle.javafx.jmx.json.JSONFactory;
import com.oracle.javafx.jmx.json.JSONWriter;
import javafx.scene.web.WebEngine;
import netscape.javascript.JSObject;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

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
        StringReader stringReader = new StringReader((String)webEngine.executeScript("JSON.stringify(" + temporaryIdentifier + ")"));
        return JSONFactory.instance().makeReader(stringReader).build().object();
    }


    public static JSObject toJSMap(WebEngine webEngine, Map<String, String> map) throws IOException {

        // JSON writer needs a map of String, Object
        Map<String, Object> returned = new HashMap<String, Object>();

        // Our writers
        StringWriter stringWriter = new StringWriter();
        JSONWriter jsonWriter = JSONFactory.instance().makeWriter(stringWriter);

        // Put all elements in the map object
        returned.putAll(map);

        // Write to a JSON object embedded inside of an array to appease WebEngine
        jsonWriter.startArray().writeObject(returned).endArray();


        JSObject o = (JSObject) webEngine.executeScript(stringWriter.toString());
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

        if (list == null || list.size() == 0)
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

    public static <T> List<T[]> toTwoDimenionalJavaListArray(JSObject jsObject) {
        ArrayList<T[]> arrayList = new ArrayList<T[]>();
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
}
