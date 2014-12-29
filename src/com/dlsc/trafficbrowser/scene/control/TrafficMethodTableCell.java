package com.dlsc.trafficbrowser.scene.control;

import com.dlsc.trafficbrowser.beans.Traffic;

public class TrafficMethodTableCell extends TrafficTableCellBase {

	@Override
	protected String lookupText1(Traffic traffic) {
		return traffic.getMethod();
	}
}
