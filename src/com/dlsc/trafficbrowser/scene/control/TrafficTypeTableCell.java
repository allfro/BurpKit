package com.dlsc.trafficbrowser.scene.control;


import com.dlsc.trafficbrowser.beans.Traffic;

public class TrafficTypeTableCell extends TrafficTableCellBase {
		
	public TrafficTypeTableCell() {
	}
	
	@Override
	protected String lookupText1(Traffic traffic) {
		return getItem().getType();
	}
}
