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

package com.redcanari.js.wrappers;

import burp.IParameter;
import burp.IRequestInfo;

import java.net.URL;
import java.util.List;

/**
 * Created by ndouba on 15-06-28.
 */
public class RequestInfoWrapper implements IRequestInfo {

    private final IRequestInfo requestInfo;

    public RequestInfoWrapper(IRequestInfo requestInfo) {
        this.requestInfo = requestInfo;
    }

    @Override
    public String getMethod() {
        return requestInfo.getMethod();
    }

    @Override
    public URL getUrl() {
        return requestInfo.getUrl();
    }

    @Override
    public List<String> getHeaders() {
        return requestInfo.getHeaders();
    }

    @Override
    public List<IParameter> getParameters() {
        return requestInfo.getParameters();
    }

    @Override
    public int getBodyOffset() {
        return requestInfo.getBodyOffset();
    }

    @Override
    public byte getContentType() {
        return requestInfo.getContentType();
    }
}
