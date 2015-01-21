package com.redcanari.js.proxies;

import javafx.application.Platform;
import netscape.javascript.JSObject;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

/**
 * Created by ndouba on 14-12-09.
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
