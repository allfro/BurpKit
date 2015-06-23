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

import com.redcanari.ui.font.FontAwesome;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.value.ObservableValue;
import javafx.concurrent.Worker;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.StackPane;
import javafx.scene.text.Font;
import javafx.scene.web.WebEngine;

/**
 * Created by ndouba on 15-01-01.
 */
public class WebURLField extends StackPane {
    private final WebEngine webEngine;
    private final TextField urlTextField;
    
    private final static String ICON_RELOAD_PAGE = FontAwesome.ICON_REPEAT;
    private final static String ICON_CANCEL_PAGE = FontAwesome.ICON_TIMES_CIRCLE;
    
    private final SimpleStringProperty buttonIcon = new SimpleStringProperty(ICON_RELOAD_PAGE);

    public WebURLField(WebEngine webEngine) {
        this.webEngine = webEngine;

        Button stopNavigation = new Button();
        stopNavigation.getStylesheets().add(getClass().getResource("/stylesheets/web_url_field.css").toExternalForm());
        stopNavigation.getStyleClass().set(0, "nav-button");
        stopNavigation.textProperty().bind(buttonIcon);
        stopNavigation.setOnMouseClicked(this::handleOnMouseClick);
        stopNavigation.setFont(Font.font("FontAwesome", 14));
        StackPane.setAlignment(stopNavigation, Pos.CENTER_RIGHT);

        urlTextField = new URLTextField(webEngine);
        HBox.setHgrow(urlTextField, Priority.ALWAYS);
        urlTextField.setStyle("-fx-padding: 0.25em 2em  0.333333em 0.416667em");
        StackPane.setAlignment(urlTextField, Pos.CENTER);

        webEngine.getLoadWorker().stateProperty().addListener(this::workerStateChanged);

        getChildren().addAll(urlTextField, stopNavigation);
    }

    private void handleOnMouseClick(MouseEvent mouseEvent) {
        switch(buttonIcon.get()) {
            case ICON_CANCEL_PAGE:
                cancelNavigation();
                break;
            case ICON_RELOAD_PAGE:
                refreshPage();
        }
    }

    private void refreshPage() {
        webEngine.reload();
    }

    private void cancelNavigation() {
        webEngine.getLoadWorker().cancel();
    }

    public void workerStateChanged(ObservableValue<? extends Worker.State> observable,
                                   Worker.State oldValue, Worker.State newValue) {
        if (newValue == Worker.State.READY || newValue == Worker.State.SCHEDULED || newValue == Worker.State.RUNNING) {
            buttonIcon.set(ICON_CANCEL_PAGE);
        } else {
            buttonIcon.set(ICON_RELOAD_PAGE);
        }
    }

    public void setEditable(boolean enabled) {
        urlTextField.setEditable(enabled);
    }
}
