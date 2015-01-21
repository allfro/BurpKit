package com.redcanari.js.proxies;

import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 14-12-09.
 */
public class IntruderPayloadGeneratorFactory extends JSProxy implements IIntruderPayloadGeneratorFactory {

    public IntruderPayloadGeneratorFactory(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public String getGeneratorName() {
        return null;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        return null;
    }

}
