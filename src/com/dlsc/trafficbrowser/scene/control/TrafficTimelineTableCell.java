package com.dlsc.trafficbrowser.scene.control;

import com.dlsc.trafficbrowser.beans.Traffic;
import com.dlsc.trafficbrowser.scene.layout.TrafficTimeline;
import javafx.scene.control.ContentDisplay;
import javafx.scene.control.TableCell;

public class TrafficTimelineTableCell extends TableCell<Traffic, Traffic> {
	private TrafficTimeline graphics;

	public TrafficTimelineTableCell(TrafficBrowser browser) {
		graphics = new TrafficTimeline(browser);
		setGraphic(graphics);
		setContentDisplay(ContentDisplay.GRAPHIC_ONLY);
	}

	@Override
	protected void updateItem(Traffic traffic, boolean empty) {
		graphics.setTraffic(traffic);
	}
}
