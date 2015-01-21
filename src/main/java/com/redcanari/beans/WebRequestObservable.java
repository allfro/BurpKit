package com.redcanari.beans;

import com.dlsc.trafficbrowser.beans.Traffic;
import javafx.collections.ObservableList;

import java.net.URL;
import java.util.Observer;

/**
 * Created by ndouba on 14-11-20.
 */
public interface WebRequestObservable {

    public void addWebRequestListener(URL scope, ObservableList<Traffic> observer);

    public void removeWebRequestListener(URL scope);

}
