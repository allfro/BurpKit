package com.redcanari.js.proxies;

import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 14-12-09.
 */
public class IntruderPayloadGeneratorFactoryJSProxy extends JSProxy implements IIntruderPayloadGeneratorFactory {
    public IntruderPayloadGeneratorFactoryJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public String getGeneratorName() {
        return (String) call("getGeneratorName");
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack intruderAttack) {
        return (IIntruderPayloadGenerator) call("createNewInstance", intruderAttack);
    }
}
