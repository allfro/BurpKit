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
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

/**
 * Created by ndouba on 14-12-09.
 */
public class SwingFXUtilities {

    public static <T> FutureTask<T> invokeLater(Callable<T> callable, JSObject callback) {
        FutureTask<T> task = new FutureTask<>(callable);

        SwingUtilities.invokeLater(() -> {
            try {
                final T result = callable.call();
                if (callback != null) {
                    Platform.runLater(() -> {
                        callback.setMember("this", callback);
                        callback.call("this", result);
                        callback.removeMember("this");
                    });
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

        });

        return task;
    }

    public static <T> FutureTask<T> invokeLater(Callable<T> callable) {
        FutureTask<T> task = new FutureTask<>(callable);

        SwingUtilities.invokeLater(task);

        return task;
    }

    public static <T> T invokeAndWait(Callable<T> callable) throws InterruptedException,
            InvocationTargetException {
        try {
            //blocks until future returns
            return invokeLater(callable).get();
        } catch (ExecutionException e) {
            Throwable t = e.getCause();

            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            } else if (t instanceof InvocationTargetException) {
                throw (InvocationTargetException) t;
            } else {
                throw new InvocationTargetException(t);
            }
        }
    }



}
