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

import javafx.collections.ListChangeListener;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.SkinBase;
import javafx.scene.control.ToolBar;
import javafx.scene.layout.*;
import javafx.scene.paint.Paint;

/**
 * Created by ndouba on 15-08-15.
 */
public class StatusBarSkin extends SkinBase<StatusBar> {
    /**
     * Constructor for all SkinBase instances.
     *
     * @param control The control for which this Skin should attach to.
     */
    protected StatusBarSkin(StatusBar control) {
        super(control);

        final ToolBar leftToolbar = new ToolBar();
        HBox.setHgrow(leftToolbar, Priority.ALWAYS);
        leftToolbar.setMinHeight(40);

        final ToolBar rightToolbar = new ToolBar();
        HBox.setHgrow(rightToolbar, Priority.ALWAYS);
        rightToolbar.setMinHeight(40);

        final HBox parent = new HBox(leftToolbar, rightToolbar);

        final ProgressBar progressBar = new ProgressBar();
        progressBar.progressProperty().bind(control.progressProperty());
        progressBar.setPrefWidth(0);
        progressBar.setMaxWidth(100);
        HBox.setHgrow(progressBar, Priority.ALWAYS);

        final Label textLabel = new Label();
        textLabel.textProperty().bind(control.textProperty());

        final Pane spacer = new Pane();
        HBox.setHgrow(spacer, Priority.SOMETIMES);

        rightToolbar.getItems().addAll(spacer, progressBar);
        rightToolbar.getItems().addAll(control.getRightItems());

        control.getLeftItems().addListener((ListChangeListener<Node>) c -> {
            while (c.next()) {
                for (Node n : c.getRemoved()) {
                    leftToolbar.getItems().remove(n);
                }
                leftToolbar.getItems().addAll(c.getAddedSubList());
            }
            getSkinnable().requestLayout();
        });

        leftToolbar.getItems().add(textLabel);
        leftToolbar.getItems().addAll(control.getLeftItems());

        control.getRightItems().addListener((ListChangeListener<Node>) c -> {
            while (c.next()) {
                for (Node n : c.getRemoved()) {
                    rightToolbar.getItems().remove(n);
                }
                for (Node n : c.getAddedSubList()) {
                    rightToolbar.getItems().add(1, n);
                }
            }
            getSkinnable().requestLayout();
        });

        progressBar.visibleProperty().bind(progressBar.progressProperty().isNotEqualTo(1));

        parent.setBorder(new Border(
                new BorderStroke(
                        Paint.valueOf("#AAA"),
                        BorderStrokeStyle.SOLID,
                        CornerRadii.EMPTY,
                        new BorderWidths(1, 0, 0, 0
                        )
                )
        ));


        getChildren().add(parent);
    }
}
