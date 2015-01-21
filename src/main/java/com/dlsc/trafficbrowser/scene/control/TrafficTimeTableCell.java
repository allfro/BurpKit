package com.dlsc.trafficbrowser.scene.control;


import com.dlsc.trafficbrowser.beans.Traffic;

public class TrafficTimeTableCell extends TrafficTableCellBase {
		
	public TrafficTimeTableCell() {
	}
	
	@Override
	protected String lookupText1(Traffic traffic) {
		return getItem().getTime();
	}
}
