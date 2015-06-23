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
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;

import java.util.ArrayList;
import java.util.List;

/**
 * @author  Nadeem Douba
 * @version 1.0
 * @since   2014-12-27.
 */
public class CircularTextField extends BaseTextField {

    int currentIndex = -1;
    private List<String> history = new ArrayList<>();


    public CircularTextField() {
        super();
        setOnKeyPressed(this::handleKeyPressed);
    }

    public void handleKeyPressed(KeyEvent event) {
        KeyCode keyCode = event.getCode();

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
            return;
        }

        switch (keyCode) {
            case ENTER:
                currentIndex = -1;
                history.add(0, getText().trim());
                break;
            case UP:
                if (history.size() == 0)
                    break;
                else if (currentIndex != history.size() - 1)
                    currentIndex++;
                setText(history.get(currentIndex));
                Platform.runLater(this::end);
                break;
            case DOWN:
                if (currentIndex != -1)
                    currentIndex--;
                setText((currentIndex == -1)?"":history.get(currentIndex));
            default:
                break;
        }
    }

}
