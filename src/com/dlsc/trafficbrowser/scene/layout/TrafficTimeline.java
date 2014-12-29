package com.dlsc.trafficbrowser.scene.layout;

import java.time.Instant;

import com.dlsc.trafficbrowser.beans.Traffic;
import com.dlsc.trafficbrowser.scene.control.TrafficBrowser;
import javafx.scene.layout.Pane;
import javafx.scene.layout.Region;

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
