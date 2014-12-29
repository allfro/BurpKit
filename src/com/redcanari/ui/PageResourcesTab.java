package com.redcanari.ui;

import com.sun.webkit.dom.*;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Worker;
import javafx.scene.control.Tab;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.web.WebEngine;
import netscape.javascript.JSObject;

import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Created by ndouba on 14-12-27.
 */
public class PageResourcesTab extends Tab {

    private final WebEngine webEngine;
    private final TableView pageResourceTableView = new TableView<PageResource>();
    private final ObservableList<PageResource> dataSource = FXCollections.observableArrayList();

    private final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_A = "document.getElementsByTagName('a');";
    private final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_IMG = "document.getElementsByTagName('img');";
    private final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_LINK = "document.getElementsByTagName('link');";
    private final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_FORM = "document.getElementsByTagName('form');";
    private final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_FRAME = "document.getElementsByTagName('frame');";
    private final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_IFRAME = "document.getElementsByTagName('iframe');";
    private final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_SCRIPT = "document.getElementsByTagName('script');";
    private final String DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_OBJECT = "document.getElementsByTagName('object');";

    public PageResourcesTab(WebEngine webEngine) {
        super("Page Resources");
        this.webEngine = webEngine;
        init();
    }

    private void init() {
        createListView();
        webEngine.getLoadWorker().stateProperty().addListener(this::workerStateChanged);
    }

    private void createListView() {
//        pageResourceTableView.setStyle("-fx-font-weight:bold;");
        TableColumn<PageResource, String> typeColumn = new TableColumn<>("Type");
        typeColumn.setCellValueFactory(new PropertyValueFactory<>("type"));

        TableColumn<PageResource, String> urlColumn = new TableColumn<>("URL");
        urlColumn.setCellValueFactory(new PropertyValueFactory<>("url"));


        pageResourceTableView.setItems(dataSource);
        pageResourceTableView.getColumns().addAll(typeColumn, urlColumn);

        VBox.setVgrow(pageResourceTableView, Priority.ALWAYS);

        setContent(pageResourceTableView);
    }

    public void workerStateChanged(ObservableValue<? extends Worker.State> observable, Worker.State oldValue, Worker.State newValue) {
        if (newValue == Worker.State.READY) {
            dataSource.clear();
        } else if (newValue == Worker.State.SUCCEEDED) {
            getStyleSheets();
            getScripts();
            getHyperlinks();
            getImages();
            getFrames();
            getIFrames();
            getObjects();
            getForms();
        }
    }

    private boolean isHttpURL(String url) {
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }

    public void getHyperlinks() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_A);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i++);
            if (o instanceof HTMLAnchorElementImpl) {
                String text = ((HTMLAnchorElementImpl) o).getText().trim();
                String href = ((HTMLAnchorElementImpl) o).getHref();
                if (isHttpURL(href)) {
                    dataSource.add(new PageResource("Anchor", href.trim()));
//                    System.out.println(text + " -> " + href.trim());
                }
            }
        }
    }

    public void getStyleSheets() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_LINK);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i++);
            if (o instanceof HTMLLinkElementImpl) {
                String href = ((HTMLLinkElementImpl) o).getHref();
                if (isHttpURL(href)) {
                    dataSource.add(new PageResource("Stylesheet", href.trim()));
//                    System.out.println("stylesheet -> " + href.trim());
                }
            }
        }
    }

    public void getScripts() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_SCRIPT);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i++);
            if (o instanceof HTMLScriptElementImpl) {
                String src = ((HTMLScriptElementImpl) o).getSrc();
                if (isHttpURL(src)) {
                    dataSource.add(new PageResource("Script", src.trim()));
//                    System.out.println("stylesheet -> " + src.trim());
                }
            }
        }
    }

    public void getImages() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_IMG);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i++);
            if (o instanceof HTMLImageElementImpl) {
                String src = ((HTMLImageElementImpl) o).getSrc();
                if (isHttpURL(src)) {
                    dataSource.add(new PageResource("Image", src.trim()));
//                    System.out.println("image -> " + src.trim());
                }
            }
        }
    }

    public void getFrames() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_FRAME);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i++);
            if (o instanceof HTMLFrameElementImpl) {
                String src = ((HTMLFrameElementImpl) o).getSrc();
                if (isHttpURL(src)) {
                    dataSource.add(new PageResource("Frame", src.trim()));
//                    System.out.println("frame -> " + src.trim());
                }
            }
        }
    }

    public void getIFrames() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_IFRAME);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i++);
            if (o instanceof HTMLIFrameElementImpl) {
                String src = ((HTMLIFrameElementImpl) o).getSrc();
                if (isHttpURL(src)) {
                    dataSource.add(new PageResource("IFrame", src.trim()));
//                    System.out.println("iframe -> " + src.trim());
                }
            }
        }
    }

    public void getObjects() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_OBJECT);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i++);
            if (o instanceof HTMLObjectElementImpl) {
                String data = ((HTMLObjectElementImpl) o).getData();
                if (isHttpURL(data)) {
                    dataSource.add(new PageResource("Object", data.trim()));
//                    System.out.println("object -> " + data.trim());
                }
            }
        }
    }

    public void getForms() {
        JSObject result = (JSObject) webEngine.executeScript(DOCUMENT_GET_ELEMENTS_BY_TAG_NAME_FORM);
        int length = (int) result.getMember("length");

        for (int i = 0; i < length; i++) {
            Object o = result.getSlot(i++);
            if (o instanceof HTMLFormElementImpl) {
                String action = ((HTMLFormElementImpl) o).getAction();
                if (isHttpURL(action)) {
                    dataSource.add(new PageResource("Form Action", action.trim()));
//                    System.err.println("Form Action -> " + action.trim());
                }
            }
        }
    }


    public static class PageResource {

        private final SimpleStringProperty type;
        private final SimpleStringProperty url;

        public PageResource(URL url) {
            Path path = Paths.get(url.getPath()).getFileName();
            String p = (path == null)?"":path.toString().replaceFirst(".+\\.?", "");

            if (p.isEmpty())
                p = "unknown";

            type = new SimpleStringProperty(p);
            this.url = new SimpleStringProperty(url.toString());
        }

        public PageResource(String type, String url) {
            this.type = new SimpleStringProperty(type);
            this.url = new SimpleStringProperty(url);
        }

        public String getType() {
            return type.get();
        }

        public void setType(String type) {
            this.type.set(type);
        }

        public String getUrl() {
            return url.get();
        }

        public void setUrl(String url) {
            this.url.set(url);
        }

    }

}
