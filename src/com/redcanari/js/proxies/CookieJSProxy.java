package com.redcanari.js.proxies;

import burp.ICookie;
import com.sun.glass.ui.Application;
import netscape.javascript.JSObject;

import java.util.Date;

/**
 * Created by ndouba on 14-12-09.
 */
public class CookieJSProxy extends JSProxy implements ICookie {

    public CookieJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public String getDomain() {
        return (String) call("getDomain");
    }

    @Override
    public Date getExpiration() {
        return (Date) call("getExpiration");
    }

    @Override
    public String getName() {
        return (String) call("getName");
    }

    @Override
    public String getValue() {
        return (String) call("getValue");
    }
}
