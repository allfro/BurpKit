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

package com.redcanari.js.proxies;

import burp.IScannerInsertionPoint;
import com.redcanari.js.Helpers;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 15-06-24.
 */
public class ScannerInsertionPointJSProxy extends JSProxy implements IScannerInsertionPoint {
    public ScannerInsertionPointJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public String getInsertionPointName() {
        return call("getInsertionPointName");
    }

    @Override
    public String getBaseValue() {
        return call("getBaseValue");
    }

    @Override
    public byte[] buildRequest(byte[] bytes) {
        return Helpers.getBytes(call("buildRequest", bytes, null));
    }

    @Override
    public int[] getPayloadOffsets(byte[] bytes) {
        return Helpers.toPrimitiveIntArray(call("getPayloadOffsets", bytes, null));
    }

    @Override
    public byte getInsertionPointType() {
        return call("getInsertionPointType");
    }
}
