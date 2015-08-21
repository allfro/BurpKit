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

package com.redcanari.ui.util;

import com.sun.glass.ui.Pixels;
import com.sun.glass.ui.Robot;
import javafx.geometry.Bounds;
import javafx.scene.Parent;
import javafx.scene.control.Control;
import javafx.scene.image.Image;
import javafx.scene.image.PixelFormat;
import javafx.scene.image.WritableImage;
import javafx.stage.Window;

/**
 * Created by ndouba on 15-08-16.
 */
public class ScreenShot {

    public static Image fullScreenCapture(Window window) {
        return pixelsToImage(getRobot().getScreenCapture(
                        (int) window.getX(),
                        (int) window.getY(),
                        (int) window.getWidth(),
                        (int) window.getHeight(),
                        true)
        );
    }

    public static Image fullScreenCapture(Parent parent) {
        Bounds controlBounds = parent.localToScreen(parent.getBoundsInLocal());
        return pixelsToImage(getRobot().getScreenCapture(
                        (int) controlBounds.getMinX(),
                        (int) controlBounds.getMinY(),
                        (int) controlBounds.getWidth(),
                        (int) controlBounds.getHeight(),
                        true)
        );
    }

    public static Image fullScreenCapture(Control control) {
        Bounds controlBounds = control.localToScreen(control.getBoundsInLocal());
        return pixelsToImage(getRobot().getScreenCapture(
                        (int) controlBounds.getMinX(),
                        (int) controlBounds.getMinY(),
                        (int) controlBounds.getWidth(),
                        (int) controlBounds.getHeight(),
                        true)
        );
    }

    private static Image pixelsToImage(Pixels pixels) {
        WritableImage image = new WritableImage(pixels.getWidth(), pixels.getHeight());
        image.getPixelWriter().setPixels(
                0, 0,
                pixels.getWidth(), pixels.getHeight(),
                PixelFormat.getIntArgbPreInstance(),
                (int[])pixels.getPixels().array(), 0,
                pixels.getWidth()
        );
        return image;
    }

    private static Robot getRobot() {
        return com.sun.glass.ui.Application.GetApplication().createRobot();
    }

}
