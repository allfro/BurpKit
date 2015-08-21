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

import javafx.beans.DefaultProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.Node;
import javafx.scene.control.Control;
import javafx.scene.control.Skin;

/**
 * Created by ndouba on 15-08-15.
 */
@DefaultProperty("leftItems")
public class StatusBar extends Control {

    ObservableList<Node> leftItems = FXCollections.observableArrayList();
    ObservableList<Node> rightItems = FXCollections.observableArrayList();
    SimpleDoubleProperty progress = new SimpleDoubleProperty(100);
    SimpleStringProperty text = new SimpleStringProperty("");

    public StatusBar() {

    }

    @Override
    protected Skin<?> createDefaultSkin() {
        return new StatusBarSkin(this);
    }

    public ObservableList<Node> getLeftItems() {
        return leftItems;
    }

    public ObservableList<Node> getRightItems() {
        return rightItems;
    }

    public Number getProgress() {
        return progress.get();
    }

    public SimpleDoubleProperty progressProperty() {
        return progress;
    }

    public String getText() {
        return text.get();
    }

    public void setText(String text) {
        this.text.set(text);
    }

    public SimpleStringProperty textProperty() {
        return text;
    }
}
