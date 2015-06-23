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

package com.redcanari.js.proxies;

import javafx.application.Platform;
import netscape.javascript.JSObject;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

/**
 * @author Nadeem Douba
 * @version 1.0
 * @since 2014-12-09.
 */
public class JSProxy {

    protected final JSObject jsObject;

    public JSProxy(JSObject jsObject) {
        this.jsObject = jsObject;
    }

    public <T> T call(String methodName, Object... args) {
        if (Platform.isFxApplicationThread())
            return (T) jsObject.call(methodName, args);
        FutureTask<T> task = new FutureTask<T>(() -> (T) jsObject.call(methodName, args));
        Platform.runLater(task);
        try {
            return task.get();
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
            return null;
        }
    }
}
