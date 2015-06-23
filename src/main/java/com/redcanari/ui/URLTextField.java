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

import javafx.beans.value.ObservableValue;
import javafx.concurrent.Worker;
import javafx.event.ActionEvent;
import javafx.scene.web.WebEngine;

/**
 * Created by ndouba on 15-01-01.
 */
public class URLTextField extends BaseTextField {

    private final WebEngine webEngine;

    public URLTextField(WebEngine webEngine) {
        this.webEngine = webEngine;
        webEngine.getLoadWorker().stateProperty().addListener(this::workerStateChanged);
        setOnAction(this::handleOnAction);
    }

    private void handleOnAction(ActionEvent actionEvent) {
        String url = getText();
        if (!url.matches("^(https?|ftp|about|javascript|data|file|burp|telnet):(//)?.*"))
            url = "http://" + url;
        webEngine.load(url);
    }

    public void workerStateChanged(ObservableValue<? extends Worker.State> observable, Worker.State oldValue, Worker.State newValue) {
        if (newValue == Worker.State.SCHEDULED) {
            textProperty().bind(webEngine.locationProperty());
        } else if (newValue != Worker.State.RUNNING) {
            textProperty().unbind();
        }
    }

    @Override
    public void requestFocus() {
        textProperty().unbind();
        super.requestFocus();
    }

}
