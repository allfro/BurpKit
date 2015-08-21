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

import javafx.beans.property.SimpleBooleanProperty;
import javafx.scene.Node;
import javafx.scene.control.SplitPane;

/**
 * Created by ndouba on 15-07-13.
 */
public class CollapsibleSplitPane extends SplitPane {

    private double lastPosition = 0.5;
    private SimpleBooleanProperty expanded = new SimpleBooleanProperty(false);

    public CollapsibleSplitPane() {
        this(null, null);
    }

    public CollapsibleSplitPane(Node upper, Node lower) {
        super(upper, lower);

        expandedProperty().addListener((observable, oldValue, newValue) -> {
            if (newValue)
                setDividerPosition(lastPosition);
            else
                setDividerPosition(1.0);
        });

        expanded.set(true);
    }

    private void setDividerPosition(double position) {
        lastPosition = getDividerPositions()[0];
        super.setDividerPosition(0, position);
    }

    public double getLastDividerPosition() {
        return lastPosition;
    }

    public void collapse() {
        expanded.set(false);
    }

    public void expand() {
        expanded.set(true);
    }

    public boolean isExpanded() {
        return expanded.get();
    }

    public SimpleBooleanProperty expandedProperty() {
        return expanded;
    }
}
