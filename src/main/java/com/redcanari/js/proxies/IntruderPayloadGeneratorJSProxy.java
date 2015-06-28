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

import burp.IIntruderPayloadGenerator;
import com.redcanari.js.Helpers;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 15-06-24.
 */
public class IntruderPayloadGeneratorJSProxy extends JSProxy implements IIntruderPayloadGenerator {

    public IntruderPayloadGeneratorJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public boolean hasMorePayloads() {
        return call("hasMorePayloads");
    }

    @Override
    public byte[] getNextPayload(byte[] bytes) {
        return Helpers.getBytes(call("getNextPayload", bytes, null));
    }

    @Override
    public void reset() {
        call("reset");
    }
}
