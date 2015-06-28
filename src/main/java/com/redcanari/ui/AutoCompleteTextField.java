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

import com.redcanari.ui.providers.AutoCompletionProvider;
import com.sun.javafx.scene.control.skin.TextFieldSkin;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.event.EventHandler;
import javafx.geometry.Point2D;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.stage.Popup;

public class AutoCompleteTextField extends CircularTextField implements EventHandler<KeyEvent> {

    private final Popup popup = new Popup();
    private final DoubleProperty caretX = new SimpleDoubleProperty();
    private final DoubleProperty caretY = new SimpleDoubleProperty();
    private final AutoCompletionProvider autoCompletionProvider;
    private final ListView<String> listView = new ListView<>();
    private ObservableList<String> completions;
    private boolean tracking = false;
    private int suggestionStart = 0;


    public AutoCompleteTextField(AutoCompletionProvider completionProvider) {
        super();
        autoCompletionProvider = completionProvider;

        popup.setAutoFix(true);
        popup.setAutoHide(true);
        popup.setHideOnEscape(true);
        popup.getContent().add(listView);

        listView.setMaxHeight(100);

        listView.setOnMouseClicked(event -> {
            autoCompletionProvider.applySuggestion(this, listView.getSelectionModel().getSelectedItem());
            reset();
        });

        setSkin(new TextFieldCaretControlSkin(this));

        caretPositionProperty().addListener((observable, oldValue, newValue) -> {
            String text = getText();
            int oldValueInt = oldValue.intValue();
            int newValueInt = newValue.intValue();

            if (oldValueInt < newValueInt && autoCompletionProvider.shouldShowPopup(text.charAt(oldValueInt)))
                suggestionStart = newValueInt;
        });

        setOnKeyReleased(this);
    }

    public int getSuggestionStart() {
        return suggestionStart;
    }


    public double getCaretX() {
        return caretX.get();
    }

    public double getCaretY() {
        return caretY.get();
    }

    private void reset() {
        popup.hide();
        tracking = false;
    }

    @Override
    public void handle(KeyEvent event) {
        KeyCode keyCode = event.getCode();
        int caret = getCaretPosition();
        if (popup.isShowing()) {
            popup.setX(getCaretX());
            popup.setY(getCaretY());
        }
        if (autoCompletionProvider.shouldShowPopup(keyCode)) {
            completions = FXCollections.observableArrayList();
            completions.addAll(autoCompletionProvider.getCompletions(this));
            FXCollections.sort(completions);
            tracking = true;
            if (completions.size() > 0) {
                if (!popup.isShowing())
                    popup.show(this, getCaretX(), getCaretY());
                listView.setItems(completions);
                listView.getSelectionModel().selectFirst();
                listView.requestFocus();
            }
        } else if ((keyCode == KeyCode.ENTER || keyCode == KeyCode.TAB) && popup.isShowing()) {
            String item = listView.getSelectionModel().getSelectedItem();
            if (item == null)
                item = listView.getItems().get(0);
            autoCompletionProvider.applySuggestion(this, item);
            reset();
        } else if ((event.getText().matches("[ -~]") || keyCode == KeyCode.BACK_SPACE) && (popup.isShowing() || tracking)) {
            if (!tracking) {
                tracking = true;
            } else if (caret < suggestionStart) {
                reset();
                return;
            }
            FilteredList<String> filteredList = completions.filtered(s -> s.startsWith(getText(suggestionStart, caret)));
            if (filteredList.size() == 0) {
                popup.hide();
                return;
            }
            else if (!popup.isShowing() && filteredList.size() > 0)
                popup.show(this, getCaretX(), getCaretY());
            listView.setItems(filteredList);
            listView.getSelectionModel().selectFirst();
            listView.requestFocus();
        } else if ((keyCode != KeyCode.UP && keyCode != KeyCode.DOWN && keyCode != KeyCode.PAGE_DOWN &&
                keyCode != KeyCode.PAGE_UP && !keyCode.isModifierKey()) && popup.isShowing()) {
            reset();
        }
    }

    protected class TextFieldCaretControlSkin extends TextFieldSkin {
        public TextFieldCaretControlSkin(TextField textField) {
            super(textField);
            caretPath.layoutBoundsProperty().addListener((observable, oldValue, newValue) -> {
                double x = newValue.getMaxX();
                double y = newValue.getMaxY();

                if (x == -1.0 || y == -1.0)
                    return;

                Point2D p = caretPath.localToScene(x, y);

                caretX.setValue(p.getX() + caretPath.getScene().getX() + caretPath.getScene().getWindow().getX());
                caretY.setValue(p.getY() + caretPath.getScene().getY() +
                        caretPath.getScene().getWindow().getY() - newValue.getHeight());
            });
        }
    }

}
