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

package com.redcanari.ui;

import javafx.application.Platform;
import javafx.scene.control.TextField;
import javafx.scene.control.TextInputDialog;
import javafx.scene.web.PromptData;

import java.util.Optional;

/**
 * Created by ndouba on 15-07-02.
 */
public class JSInputDialog extends TextInputDialog {

    public JSInputDialog() {
        setTitle("JavaScript Prompt");
    }

    public String prompt(PromptData promptData) {
        // Set the masthead to the user's prompt message.
        setHeaderText(promptData.getMessage());

        // Set the textfield to the default value
        TextField textField = getEditor();
        textField.setText(promptData.getDefaultValue());

        // Request focus on the textfield so the user can type their response right away.
        Platform.runLater(() -> {
            textField.requestFocus();
            textField.selectAll();
        });

        // Show and wait for the result and then return a string or null
        Optional<String> result = super.showAndWait();
        return (result.isPresent())?result.get():null;
    }
}
