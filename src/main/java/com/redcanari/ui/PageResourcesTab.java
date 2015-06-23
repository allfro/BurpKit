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

import burp.BurpExtender;
import com.redcanari.js.BurpExtenderCallbacksBridge;
import com.redcanari.util.HttpUtils;
import com.sun.webkit.dom.*;
import javafx.application.Platform;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Worker;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.image.ImageView;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.web.WebEngine;
import netscape.javascript.JSObject;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Created by ndouba on 14-12-27.
 */
public class PageResourcesTab extends Tab {

    private final WebEngine webEngine;
    private final TableView<PageResource> pageResourceTableView = new TableView<>();
    private final ObservableList<PageResource> dataSource = FXCollections.observableArrayList();
    private final BurpExtenderCallbacksBridge callbacks;

    private static final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_A = "document.getElementsByTagName('a');";
    private static final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_IMG = "document.getElementsByTagName('img');";
    private static final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_LINK = "document.getElementsByTagName('link');";
    private static final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_FORM = "document.getElementsByTagName('form');";
    private static final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_FRAME = "document.getElementsByTagName('frame');";
    private static final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_IFRAME = "document.getElementsByTagName('iframe');";
    private static final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_SCRIPT = "document.getElementsByTagName('script');";
    private static final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_OBJECT = "document.getElementsByTagName('object');";


    public PageResourcesTab(WebEngine webEngine) {
        super("Page Resources");
        this.webEngine = webEngine;
        this.callbacks = new BurpExtenderCallbacksBridge(webEngine, BurpExtender.getBurpExtenderCallbacks());
        init();
    }

    private void init() {
        createListView();
        webEngine.getLoadWorker().stateProperty().addListener(this::workerStateChanged);
    }

    private void createListView() {
        TableColumn<PageResource, PageResource> typeColumn = new TableColumn<>("Type");
        typeColumn.setCellValueFactory(new PropertyValueFactory<>("me"));
        typeColumn.setCellFactory(param -> new PageResourceTypeTableCell());
        typeColumn.setPrefWidth(24);

        TableColumn<PageResource, String> urlColumn = new TableColumn<>("URL");
        urlColumn.setCellValueFactory(new PropertyValueFactory<>("url"));
        urlColumn.setPrefWidth(800-24);

        pageResourceTableView.getStylesheets().add(getClass().getResource("/stylesheets/page_resources.css").toExternalForm());
        pageResourceTableView.setItems(dataSource);
        pageResourceTableView.getColumns().addAll(typeColumn, urlColumn);
        pageResourceTableView.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);

        MenuItem sendToSpiderMenuItem = new MenuItem("Send To Spider");
        sendToSpiderMenuItem.setOnAction(event -> {
            ObservableList<PageResource> selectedItems = pageResourceTableView.getSelectionModel().getSelectedItems();
            for (PageResource selectedItem : selectedItems) {
                try {
                    callbacks.sendToSpider(selectedItem.getUrl());
                } catch (MalformedURLException e) {
                    e.printStackTrace();
                }
            }
        });

        MenuItem sendToRepeaterMenuItem = new MenuItem("Send To Repeater");
        sendToRepeaterMenuItem.setOnAction(event -> {
            ObservableList<PageResource> selectedItems = pageResourceTableView.getSelectionModel().getSelectedItems();
            for (PageResource selectedItem : selectedItems) {
                try {
                    callbacks.sendUrlToRepeater(selectedItem.getUrl(), null);
                } catch (URISyntaxException | IOException e) {
                    e.printStackTrace();
                }
            }
        });

        MenuItem sendToIntruderMenuItem = new MenuItem("Send To Intruder");
        sendToIntruderMenuItem.setOnAction(event -> {
            ObservableList<PageResource> selectedItems = pageResourceTableView.getSelectionModel().getSelectedItems();
            for (PageResource selectedItem : selectedItems) {
                try {
                    callbacks.sendUrlToIntruder(selectedItem.getUrl());
                } catch (URISyntaxException | IOException e) {
                    e.printStackTrace();
                }
            }
        });

        MenuItem doActiveScanMenuItem = new MenuItem("Do Active Scan");
        doActiveScanMenuItem.setOnAction(event -> {
            ObservableList<PageResource> selectedItems = pageResourceTableView.getSelectionModel().getSelectedItems();
            for (PageResource selectedItem : selectedItems) {
                try {
                    callbacks.doActiveUrlScan(selectedItem.getUrl(), null);
                } catch (URISyntaxException | IOException e) {
                    e.printStackTrace();
                }
            }
        });

        pageResourceTableView.setContextMenu(new ContextMenu(
                sendToSpiderMenuItem,
                sendToRepeaterMenuItem,
                sendToIntruderMenuItem,
                doActiveScanMenuItem
        ));

        VBox.setVgrow(pageResourceTableView, Priority.ALWAYS);

        setContent(pageResourceTableView);
    }

    public void workerStateChanged(ObservableValue<? extends Worker.State> observable, Worker.State oldValue, Worker.State newValue) {
        if (newValue == Worker.State.SCHEDULED) {
            if (!dataSource.isEmpty()) {
                pageResourceTableView.scrollTo(0);
                dataSource.clear();
            }
        } else if (newValue == Worker.State.SUCCEEDED) {
            Platform.runLater(() -> {
                getScripts();
                getStyleSheets();
                getHyperlinks();
                getImages();
                getFrames();
                getIFrames();
                getObjects();
                getForms();
            });
        }
    }



    public void getHyperlinks() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_A);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i);
            if (o instanceof HTMLAnchorElementImpl) {
                String text = ((HTMLAnchorElementImpl) o).getText().trim();
                String href = ((HTMLAnchorElementImpl) o).getHref();
                if (HttpUtils.isHttpURL(href)) {
                    dataSource.add(new PageResource(PageResource.TYPE_ANCHOR, href.trim()));
//                    System.err.println("Anchor(text="+text+")" + " -> " + href.trim());
                }
            }
        }
    }

    public void getStyleSheets() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_LINK);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i);
            if (o instanceof HTMLLinkElementImpl) {
                String href = ((HTMLLinkElementImpl) o).getHref();
                if (HttpUtils.isHttpURL(href)) {
                    dataSource.add(new PageResource(PageResource.TYPE_STYLESHEET, href.trim()));
//                    System.err.println("Stylesheet -> " + href.trim());
                }
            }
        }
    }

    public void getScripts() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_SCRIPT);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i);
            if (o instanceof HTMLScriptElementImpl) {
                String src = ((HTMLScriptElementImpl) o).getSrc();
                if (HttpUtils.isHttpURL(src)) {
                    dataSource.add(new PageResource(PageResource.TYPE_SCRIPT, src.trim()));
//                    System.err.println("Script -> " + src.trim());
                }
            }
        }
    }

    public void getImages() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_IMG);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i);
            if (o instanceof HTMLImageElementImpl) {
                String src = ((HTMLImageElementImpl) o).getSrc();
                if (HttpUtils.isHttpURL(src)) {
                    dataSource.add(new PageResource(PageResource.TYPE_IMAGE, src.trim()));
//                    System.err.println("Image -> " + src.trim());
                }
            }
        }
    }

    public void getFrames() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_FRAME);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i);
            if (o instanceof HTMLFrameElementImpl) {
                String src = ((HTMLFrameElementImpl) o).getSrc();
                if (HttpUtils.isHttpURL(src)) {
                    dataSource.add(new PageResource(PageResource.TYPE_FRAME, src.trim()));
//                    System.err.println("Frame -> " + src.trim());
                }
            }
        }
    }

    public void getIFrames() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_IFRAME);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i);
            if (o instanceof HTMLIFrameElementImpl) {
                String src = ((HTMLIFrameElementImpl) o).getSrc();
                if (HttpUtils.isHttpURL(src)) {
                    dataSource.add(new PageResource(PageResource.TYPE_IFRAME, src.trim()));
//                    System.err.println("IFrame -> " + src.trim());
                }
            }
        }
    }

    public void getObjects() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_OBJECT);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i);
            if (o instanceof HTMLObjectElementImpl) {
                String data = ((HTMLObjectElementImpl) o).getData();
                if (HttpUtils.isHttpURL(data)) {
                    dataSource.add(new PageResource(PageResource.TYPE_OBJECT, data.trim()));
//                    System.err.println("Object -> " + data.trim());
                }
            }
        }
    }

    public void getForms() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_FORM);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i);
            if (o instanceof HTMLFormElementImpl) {
                String action = ((HTMLFormElementImpl) o).getAction();
                if (HttpUtils.isHttpURL(action)) {
                    dataSource.add(new PageResource(PageResource.TYPE_FORM, action.trim()));
//                    System.err.println("Form Action -> " + action.trim());
                }
            }
        }
    }


    public static class PageResource {

        private static final String TYPE_SCRIPT = "Script";
        private static final String TYPE_IMAGE = "Image";
        private static final String TYPE_FRAME = "Frame";
        private static final String TYPE_IFRAME = "IFrame";
        private static final String TYPE_STYLESHEET = "Stylesheet";
        private static final String TYPE_OBJECT = "Object";
        private static final String TYPE_FORM = "Form Action";
        private static final String TYPE_ANCHOR = "Hyperlink";
        private static final String TYPE_UNKNOWN = "Unknown";



        private String type;
        private String url;

        public PageResource(URL url) {
            Path path = Paths.get(url.getPath()).getFileName();
            String p = (path == null)?"":path.toString().replaceFirst(".+\\.?", "");

            if (p.isEmpty())
                p = TYPE_UNKNOWN;

            type = p;
            this.url = url.toString();
        }

        public PageResource(String type, String url) {
            this.type = type;
            this.url = url;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getUrl() {
            return url;
        }

        public String getStyleSheet() {
            switch(type) {
                case TYPE_ANCHOR:
                    return "page-resource-type-hyperlink";
                case TYPE_FORM:
                    return "page-resource-type-form";
                case TYPE_FRAME:
                case TYPE_IFRAME:
                    return "page-resource-type-frame";
                case TYPE_IMAGE:
                    return "page-resource-type-image";
                case TYPE_OBJECT:
                    return "page-resource-type-object";
                case TYPE_SCRIPT:
                    return "page-resource-type-script";
                case TYPE_STYLESHEET:
                    return "page-resource-type-stylesheet";
            }
            return "page-type-unknown";
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public PageResource getMe() {
            return this;
        }

    }

    private class PageResourceTypeTableCell extends TableCell<PageResource, PageResource> {
        private final ImageView imageView = new ImageView();
//        private final Label typeLabel = new Label();

        public PageResourceTypeTableCell() {
//            VBox vbox = new VBox();
//            vbox.getChildren().addAll(imageView);//, typeLabel);
//            vbox.setAlignment(Pos.CENTER);
            setGraphic(imageView);
            setAlignment(Pos.CENTER);
            setContentDisplay(ContentDisplay.GRAPHIC_ONLY);
        }

        @Override
        protected void updateItem(PageResource pageResource, boolean empty) {
            super.updateItem(pageResource, empty);

            if (!empty && pageResource != null) {
//                typeLabel.setText(pageResource.getType());
                imageView.getStyleClass().setAll(pageResource.getStyleSheet());
                setTooltip(new Tooltip(pageResource.getType()));
            }
        }
    }
}
