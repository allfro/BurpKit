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

import burp.ITextEditor;
import javafx.application.Platform;

import javax.swing.*;
import java.awt.*;

/**
 * Created by ndouba on 15-06-25.
 */
public class TextEditorWrapper implements ITextEditor {

    final ITextEditor textEditor;
    byte[] text = null;

    public TextEditorWrapper(ITextEditor textEditor) {
        this.textEditor = textEditor;
        textEditor.getComponent().addHierarchyListener(e -> {
            text = textEditor.getText();
        });
    }

    @Override
    public Component getComponent() {
        return textEditor.getComponent();
    }

    @Override
    public void setEditable(boolean b) {
        if (Platform.isFxApplicationThread())
            SwingUtilities.invokeLater(() -> textEditor.setEditable(b));
        else
            textEditor.setEditable(b);
    }

    @Override
    public void setText(byte[] bytes) {
        text = bytes;
        if (Platform.isFxApplicationThread())
            SwingUtilities.invokeLater(() -> textEditor.setText(bytes));
        else
            textEditor.setText(bytes);
    }

    @Override
    public byte[] getText() {
        if (Platform.isFxApplicationThread())
            return text;
        return textEditor.getText();
    }

    @Override
    public boolean isTextModified() {
        return textEditor.isTextModified();
    }

    @Override
    public byte[] getSelectedText() {
        return textEditor.getSelectedText();
    }

    @Override
    public int[] getSelectionBounds() {
        return textEditor.getSelectionBounds();
    }

    @Override
    public void setSearchExpression(String s) {
        if (Platform.isFxApplicationThread())
            SwingUtilities.invokeLater(() -> textEditor.setSearchExpression(s));
        else
            textEditor.setSearchExpression(s);
    }
}
