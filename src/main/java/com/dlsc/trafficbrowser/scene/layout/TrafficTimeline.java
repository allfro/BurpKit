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

package com.dlsc.trafficbrowser.scene.layout;

import com.dlsc.trafficbrowser.beans.Traffic;
import com.dlsc.trafficbrowser.scene.control.TrafficBrowser;
import javafx.scene.layout.Pane;
import javafx.scene.layout.Region;

import java.time.Instant;

public class TrafficTimeline extends Pane {
	private Region timebar = new Region();
	private Traffic traffic;
	private TrafficBrowser browser;

	public TrafficTimeline(TrafficBrowser browser) {
		this.browser = browser;

		timebar.setManaged(false);
		getChildren().add(timebar);
	}

	public void setTraffic(Traffic traffic) {
		this.traffic = traffic;
		timebar.setVisible(traffic != null);
		if (traffic != null) {
			timebar.getStyleClass().setAll("timebar", traffic.getBarStyle());
			requestLayout();			
		}
	}
	
	@Override
	protected void layoutChildren() {
		super.layoutChildren();

		if (traffic != null) {
			Instant startTime = browser.getStartTime();
			Instant endTime = browser.getEndTime();

			double mpp = (endTime.toEpochMilli() - startTime.toEpochMilli()) / getWidth();

			double x1 = (traffic.getStartTime().toEpochMilli() - startTime
					.toEpochMilli()) / mpp;
			double x2 = (traffic.getEndTime().toEpochMilli() - startTime
					.toEpochMilli()) / mpp;
			double barHeight = timebar.getPrefHeight();
			double y = (getHeight() - barHeight) / 2;

			timebar.resizeRelocate(x1, y, x2 - x1, barHeight);
		}
	}
}
