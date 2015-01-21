package com.dlsc.trafficbrowser.scene.control;

import java.time.Instant;

import com.dlsc.trafficbrowser.beans.Traffic;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.Control;
import javafx.scene.control.Skin;

public class TrafficBrowser extends Control {

	public TrafficBrowser() {
		getStylesheets().add(
				TrafficBrowser.class.
						getResource("/com/dlsc/trafficbrowser/resource/stylesheets/traffic.css").toExternalForm()
		);
	}
	
	@Override
	protected Skin<TrafficBrowser> createDefaultSkin() {
		return new TrafficBrowserSkin(this);
	}
	
	private final ObjectProperty<Instant> startTime = new SimpleObjectProperty<>(this, "startTime", Instant.now());
	
	public final ObjectProperty<Instant> startTimeProperty() {
		return startTime;
	}
	
	public final Instant getStartTime() {
		return startTimeProperty().get();
	}
	
	public final void setStartTime(Instant time) {
		startTimeProperty().set(time);
	}
	
	private final ObjectProperty<Instant> endTime = new SimpleObjectProperty<>(this, "endTime", Instant.now());
	
	public final ObjectProperty<Instant> endTimeProperty() {
		return endTime;
	}
	
	public final Instant getEndTime() {
		return endTimeProperty().get();
	}
	
	public final void setEndTime(Instant time) {
		endTimeProperty().set(time);
	}
	
	private ObservableList<Traffic> traffic = FXCollections.observableArrayList();
	
	public ObservableList<Traffic> getTraffic() {
		return traffic;
	}
}
