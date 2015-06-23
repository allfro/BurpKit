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

import javafx.scene.control.TextField;
import javafx.scene.input.KeyEvent;
import javafx.scene.input.MouseEvent;

/**
 * Created by ndouba on 15-01-01.
 */
public class BaseTextField extends TextField {

    private boolean focusWasRequested = false;

    public BaseTextField() {
        setOnMouseClicked(this::handleMouseClick);
        setOnKeyPressed(this::handleKeyPressed);
    }

    private void handleKeyPressed(KeyEvent event) {
        if (event.isControlDown()) {
            switch(event.getCode()) {
                case C:
                    copy();
                    break;
                case V:
                    paste();
                    break;
                case X:
                    cut();
                    break;
                case A:
                    selectAll();
            }
        }
    }

    private void handleMouseClick(MouseEvent mouseEvent) {
        if (!focusWasRequested)
            return;
        focusWasRequested = false;
        if (!getText().isEmpty())
            selectAll();
    }

    @Override
    public void requestFocus() {
        super.requestFocus();
        focusWasRequested = true;
    }

}
