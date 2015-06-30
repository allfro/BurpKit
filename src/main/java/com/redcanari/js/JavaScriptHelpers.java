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

package com.redcanari.js;

import com.redcanari.util.ResourceUtils;
import javafx.application.Platform;
import javafx.scene.web.WebEngine;
import javafx.stage.FileChooser;
import javafx.util.Pair;
import netscape.javascript.JSObject;
import org.controlsfx.dialog.Dialogs;

import javax.swing.*;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Optional;

/**
 * Created by ndouba on 15-05-16.
 */
public class JavaScriptHelpers {


    private final LocalJSObject locals;
    private final LocalJSObject globals;

    private final WebEngine webEngine;

    public JavaScriptHelpers(WebEngine webEngine) {
        this.webEngine = webEngine;
        globals = GlobalJSObject.getGlobalJSObject(webEngine);
        locals = new LocalJSObject(webEngine);
    }

    public byte[] httpGetBytes(String url) throws IOException {
        URLConnection uc = new URL(url).openConnection();
        uc.setRequestProperty("User-Agent", webEngine.getUserAgent());
        return Helpers.convertStreamToBytes(uc.getInputStream());
    }

    public String httpGetString(String url) throws IOException {
        URLConnection uc = new URL(url).openConnection();
        uc.setRequestProperty("User-Agent", webEngine.getUserAgent());
        return Helpers.convertStreamToString(uc.getInputStream());
    }

    public void require(String url) throws IOException {
        webEngine.executeScript(httpGetString(url));
    }

    public void requireLib(String library) throws IOException {
        webEngine.executeScript(
                ResourceUtils.getResourceContentsAsString("/scripts/" + library + ".js")
        );
    }

    public String saveFileDialog(String title) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle(title);
        File file = fileChooser.showSaveDialog(null);
        return (file == null)?null:file.toString();
    }

    public String openFileDialog(String title) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle(title);
        File file = fileChooser.showOpenDialog(null);
        return (file == null)?null:file.toString();
    }

    public JSObject openMultipleDialog(String title) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle(title);
        List<File> files = fileChooser.showOpenMultipleDialog(null);
        return (files == null)? (JSObject) webEngine.executeScript("new Array") :Helpers.toJSArray(webEngine, files);
    }

    public void writeToFile(String file, String data) throws IOException {
        Files.write(new File(file).toPath(), data.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    public String readFromFile(String file) throws IOException {
        return new String(Files.readAllBytes(new File(file).toPath()));
    }

    public void appendToFile(String file, String data) throws IOException {
        Files.write(new File(file).toPath(), data.getBytes(), StandardOpenOption.APPEND, StandardOpenOption.CREATE);
    }

    public void loginPrompt(JSObject callback) {
        Dialogs.create().showLogin(new Pair<>("", ""), (params) -> {
            callback.call("call", null, params.getKey(), params.getValue());
            return null;
        });
    }

    public LocalJSObject locals() {
        return locals;
    }

    public LocalJSObject globals() {
        return globals;
    }

    public String prompt(String question) {
        Optional<String> result = Dialogs.create()
                .masthead(question)
                .title("Input Required!")
                .showTextInput();
        return result.get();
    }

    protected boolean isFunction(Object object) {
        if (!(object instanceof JSObject))
            return false;
        JSObject checker = (JSObject) webEngine.executeScript("(function(obj){ return typeof obj === 'function' })");
        return (boolean) checker.call("call", null, object);
    }

    public JMenuItem createJMenuItem(String caption, JSObject handler) {
        JMenuItem menuItem = new JMenuItem();
        menuItem.setText(caption);
        if (isFunction(handler))
            menuItem.addActionListener(e -> Platform.runLater(() -> handler.call("call", null, e)));
        else
            menuItem.addActionListener(e -> Platform.runLater(() -> handler.call("actionPerformed", e)));
        return menuItem;
    }

//    public JMenuItem createJCheckBoxMenuItem(String caption, JSObject handler) {
//        JMenuItem menuItem = new JCheckBoxMenuItem();
//        menuItem.setText(caption);
//        menuItem.addActionListener(e -> Platform.runLater(() -> handler.call("actionPerformed", e)));
//        return menuItem;
//    }
//
//    public JMenuItem createJRadioButtonMenuItem(String caption, JSObject handler) {
//        JMenuItem menuItem = new JRadioButtonMenuItem();
//        menuItem.setText(caption);
//        menuItem.addActionListener(e -> Platform.runLater(() -> handler.call("actionPerformed", e)));
//        return menuItem;
//    }


    public String homeDirectory() {
        return System.getProperty("user.home");
    }

    public String pathJoin(String first, JSObject pathList) {
        String[] paths = Helpers.toJavaArray(pathList, String.class);
        return Paths.get(first, paths).toAbsolutePath().toString();
    }

    public String toString() {
        return "[object JavaScriptHelpers]";
    }
    
}
