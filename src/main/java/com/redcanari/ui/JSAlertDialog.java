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

import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Bounds;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.effect.BoxBlur;
import javafx.scene.effect.DropShadow;
import javafx.scene.layout.Pane;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.Window;

/**
 * Created by ndouba on 15-07-02.
 */
public class JSAlertDialog {

    final Alert alertBox = new Alert(Alert.AlertType.INFORMATION);
    final Stage stage = new Stage(StageStyle.UNDECORATED);
    final Parent owner;

    public JSAlertDialog(Parent owner) {
        this.owner = owner;

        alertBox.initStyle(StageStyle.UNDECORATED);
        alertBox.setHeaderText("JavaScript Alert");

        Pane alertPane = alertBox.getDialogPane();

        stage.setScene(alertPane.getScene());
        stage.setAlwaysOnTop(true);
        stage.initModality(Modality.WINDOW_MODAL);
        stage.initOwner(owner.getScene().getWindow());
        stage.getScene().getRoot().setEffect(new DropShadow());

        Bounds bounds = owner.localToScreen(owner.getBoundsInLocal());

        alertPane.layoutBoundsProperty().addListener(l -> {
            stage.setX(bounds.getMinX() + (bounds.getWidth() - alertPane.getWidth()) / 2);
            stage.setY(bounds.getMinY() + (bounds.getHeight() - alertPane.getHeight()) / 2);
        });

        owner.getScene().getWindow().xProperty().addListener((observable) -> {
            Bounds bounds1 = owner.localToScreen(owner.getBoundsInLocal());
            stage.setX(bounds1.getMinX() + (bounds1.getWidth() - alertPane.getWidth()) / 2);
        });

        owner.getScene().getWindow().yProperty().addListener((observable) -> {
            Bounds bounds2 = owner.localToScreen(owner.getBoundsInLocal());
            stage.setY(bounds2.getMinY() + (bounds2.getHeight() - alertPane.getHeight()) / 2);
        });

        ((Button)((ButtonBar)alertBox
                .getDialogPane()
                .getChildren()
                .get(2))
                .getButtons()
                .get(0))
                .setOnAction(e -> stage.close());
    }

    public void alert(String message) {
        owner.setEffect(new BoxBlur());
        alertBox.setContentText(message);
        stage.showAndWait();
        owner.setEffect(null);
    }
}
