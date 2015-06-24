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
import com.dlsc.trafficbrowser.scene.layout.TrafficTimeline;
import javafx.scene.control.ContentDisplay;
import javafx.scene.control.TableCell;


/**
 * @author Dirk Lemmermann
 * @since 2015-01-24
 * @version 1.0
 */
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
