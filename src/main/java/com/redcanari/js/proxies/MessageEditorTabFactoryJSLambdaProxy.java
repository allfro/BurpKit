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

import burp.*;
import com.redcanari.js.Helpers;
import com.redcanari.js.wrappers.MessageEditorWrapper;
import com.redcanari.js.wrappers.TextEditorWrapper;
import javafx.application.Platform;
import netscape.javascript.JSObject;

import java.awt.*;

/**
 * Created by ndouba on 14-12-09.
 */
public class MessageEditorTabFactoryJSLambdaProxy extends JSProxy implements IMessageEditorTabFactory {

    public MessageEditorTabFactoryJSLambdaProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return Helpers.<IMessageEditorTab>wrapInterface(
                call(
                        "call",
                        null,
                        controller,
                        editable,
                        new TextEditorWrapper(BurpExtender.getBurpExtenderCallbacks().createTextEditor())
                ),
                MessageEditorTabJSProxy.class
        );
    }

    /*public class EditorFactory {

        private final ITextEditor textEditor;
        private final IMessageEditor messageEditor;

        public ITextEditor getTextEditor() {
            return textEditor;
        }

        public IMessageEditor getMessageEditor() {
            return messageEditor;
        }

        public EditorFactory(IMessageEditorController controller, boolean editable) {
            textEditor = new TextEditorWrapper(BurpExtender.getBurpExtenderCallbacks().createTextEditor());
            messageEditor = new MessageEditorWrapper(BurpExtender.getBurpExtenderCallbacks().createMessageEditor(controller, editable));
        }

    }*/
}
