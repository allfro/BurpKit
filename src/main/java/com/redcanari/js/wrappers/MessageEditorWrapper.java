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

package com.redcanari.js.wrappers;

import burp.IMessageEditor;
import javafx.application.Platform;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * Created by ndouba on 15-06-27.
 */
public class MessageEditorWrapper implements IMessageEditor {

    private final IMessageEditor messageEditor;
    private byte[] text;

    public MessageEditorWrapper(IMessageEditor messageEditor) {
        this.messageEditor = messageEditor;
        this.messageEditor.getComponent().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseExited(MouseEvent e) {
                super.mouseExited(e);
                text = messageEditor.getMessage();
            }
        });
    }

    @Override
    public Component getComponent() {
        return messageEditor.getComponent();
    }

    @Override
    public void setMessage(byte[] message, boolean isRequest) {
        text = message;
        if (Platform.isFxApplicationThread())
            SwingUtilities.invokeLater(() -> messageEditor.setMessage(message, isRequest));
        else
            messageEditor.setMessage(message, isRequest);
    }

    @Override
    public byte[] getMessage() {
        if (Platform.isFxApplicationThread())
            return text;
        return messageEditor.getMessage();
    }

    @Override
    public boolean isMessageModified() {
        return messageEditor.isMessageModified();
    }

    @Override
    public byte[] getSelectedData() {
        return messageEditor.getSelectedData();
    }
}
