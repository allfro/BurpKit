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

import burp.IMessageEditorTab;
import com.redcanari.js.Helpers;
import netscape.javascript.JSObject;

import java.awt.*;

/**
 * Created by ndouba on 15-06-24.
 */
public class MessageEditorTabJSProxy extends JSProxy implements IMessageEditorTab {

    public MessageEditorTabJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public String getTabCaption() {
        return call("getTabCaption");
    }

    @Override
    public Component getUiComponent() {
        return call("getUiComponent");
    }

    @Override
    public boolean isEnabled(byte[] bytes, boolean b) {
        return call("isEnabled", bytes, b);
    }

    @Override
    public void setMessage(byte[] bytes, boolean b) {
        call("setMessage", bytes, b);
    }

    @Override
    public byte[] getMessage() {
        return Helpers.getBytes(call("getMessage"));
    }

    @Override
    public boolean isModified() {
        return call("isModified");
    }

    @Override
    public byte[] getSelectedData() {
        return Helpers.getBytes(call("getSelectedData"));
    }
}
