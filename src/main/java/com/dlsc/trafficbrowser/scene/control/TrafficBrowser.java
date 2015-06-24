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

package com.dlsc.trafficbrowser.scene.control;

import com.dlsc.trafficbrowser.beans.Traffic;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.Control;
import javafx.scene.control.Skin;

import java.time.Instant;


/**
 * @author Dirk Lemmermann
 * @since 2015-01-24
 * @version 1.0
 */
public class TrafficBrowser extends Control {

	public TrafficBrowser() {
		getStylesheets().add(
				TrafficBrowser.class.
						getResource("/stylesheets/traffic.css").toExternalForm()
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
