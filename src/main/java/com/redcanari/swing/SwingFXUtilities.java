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

package com.redcanari.swing;

import javafx.application.Platform;
import netscape.javascript.JSObject;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.*;

/**
 * Created by ndouba on 14-12-09.
 */
public class SwingFXUtilities {

    public static <T> void invokeLater(Callable<T> callable, JSObject callback) {
        SwingUtilities.invokeLater(() -> {
            try {
                final T result = callable.call();
                if (callback != null) {
                    Platform.runLater(() -> callback.call("call", null, result));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    public static <T> T invokeAndWait(Callable<T> callable) throws TimeoutException, ExecutionException, InterruptedException {
        //blocks until future returns
        FutureTask<T> task = new FutureTask<>(callable);
        SwingUtilities.invokeLater(task);
        return task.get();
    }



}
