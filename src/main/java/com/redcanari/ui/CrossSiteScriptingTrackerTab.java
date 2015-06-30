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

import com.redcanari.tainter.Tainter;
import javafx.collections.*;
import javafx.scene.control.Tab;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebEvent;

import java.util.HashMap;
import java.util.HashSet;

/**
 * Created by ndouba on 14-12-16.
 */
public class CrossSiteScriptingTrackerTab extends Tab {

    private final TreeView<String> treeView = new TreeView<>();
    private final TreeItem<String> root = new TreeItem<>("Detected Taints",
            new ImageView(new Image(getClass().getResourceAsStream("/images/world.png"))));
    private final Image fireImage = new Image(getClass().getResourceAsStream("/images/element_fire.png"));
    private final Tainter tainter = Tainter.getInstance();
    private final ObservableMap<String, ObservableSet<String>> dataSource = FXCollections.observableMap(new HashMap<>());
    private final WebEngine webEngine;

    public CrossSiteScriptingTrackerTab(WebEngine webEngine) {
        super("XSS Tracker");
        this.webEngine = webEngine;
        init();
    }

    private void init() {
        createTreeView();
        setContent(treeView);
    }

    private void createTreeView() {
        root.setExpanded(true);
        treeView.setRoot(root);
        createDataSource();
    }

    private void createDataSource() {
        dataSource.addListener((MapChangeListener<String, ObservableSet<String>>) change -> {
            if (!change.wasAdded())
                return;

            String taintId = change.getKey();
            ObservableSet<String> items = change.getValueAdded();
            final TreeItem<String> treeItem = new TreeItem<>(taintId + " (originally from: " + tainter.get(taintId) + ")", new ImageView(fireImage));

            root.getChildren().add(treeItem);

            for (String s : items) {
                treeItem.getChildren().add(new TreeItem<>(s, new ImageView(fireImage)));
            }

            items.addListener((SetChangeListener<String>) c -> {
                if (c.wasAdded())
                    treeItem.getChildren().add(new TreeItem<>(c.getElementAdded(), new ImageView(fireImage)));
            });
        });
    }

    public void handleAlert(WebEvent<String> event) {
        String message = event.getData();
        if (tainter.containsKey(message)) {
            ObservableSet<String> urls;
            if (!dataSource.containsKey(message)) {
                urls = FXCollections.observableSet(new HashSet<>());
                urls.add(webEngine.getLocation()); // Avoid triggering another event for adding one item.
                dataSource.put(message, urls);
            } else {
                urls = dataSource.get(message);
                urls.add(webEngine.getLocation());
            }
        }
    }

    public void clear() {
        if (!dataSource.isEmpty()) {
            dataSource.clear();
            root.getChildren().clear();
        }
    }
}
