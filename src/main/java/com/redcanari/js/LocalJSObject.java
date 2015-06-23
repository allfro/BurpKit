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

import javafx.scene.web.WebEngine;
import netscape.javascript.JSObject;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by ndouba on 15-06-17.
 */
public class LocalJSObject {

    private final ConcurrentHashMap<Object, Object> hashMap;
    private final WebEngine webEngine;

    public LocalJSObject(WebEngine webEngine) {
        hashMap = new ConcurrentHashMap<>();
        this.webEngine = webEngine;
    }

    public LocalJSObject(WebEngine webEngine, ConcurrentHashMap<Object, Object> hashMap) {
        this.webEngine = webEngine;
        this.hashMap = hashMap;
    }



    public Object get(Object key) {
        return hashMap.get(key);
    }

    public void put(Object key, Object value) {
        if (key instanceof JSObject)
            key = key.toString();
        if (value instanceof JSObject)
            value = value.toString();
        hashMap.put(key, value);
    }

    public void clear() {
        hashMap.clear();
    }

    public JSObject keys() {
        return Helpers.toJSArray(webEngine, hashMap.keySet().toArray());
    }

    public JSObject values() {
        return Helpers.toJSArray(webEngine, hashMap.values().toArray());
    }

    public Object getOrDefault(Object key, Object defaultValue) {
        if (key instanceof JSObject)
            key = key.toString();
        return hashMap.getOrDefault(key, defaultValue);
    }

    public boolean contains(Object value) {
        if (value instanceof JSObject)
            value = value.toString();
        return hashMap.contains(value);
    }

    public boolean containsKey(Object key) {
        if (key instanceof JSObject)
            key = key.toString();
        return hashMap.containsKey(key);
    }

    public String toString() {
        return hashMap.toString();
    }

    public void remove(Object key) {
        if (key instanceof JSObject)
            key = key.toString();
        hashMap.remove(key);
    }

}
