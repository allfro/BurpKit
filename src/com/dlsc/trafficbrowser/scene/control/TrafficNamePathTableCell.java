package com.dlsc.trafficbrowser.scene.control;


import com.dlsc.trafficbrowser.beans.Traffic;

public class TrafficNamePathTableCell extends TrafficTableCellBase {
		
	public TrafficNamePathTableCell() {
	}

	@Override
	protected String lookupImageStyle(Traffic traffic) {
		return traffic.getStyle();
	}
	
	@Override
	protected String lookupText1(Traffic traffic) {
		return getItem().getName();
	}
	
	@Override
	protected String lookupText2(Traffic traffic) {
		return getItem().getPath();
	}
}
