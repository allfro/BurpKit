# BurpKit

## Introduction
Welcome to the next generation of web application penetration testing - using WebKit to own the web.
BurpKit is a BurpSuite plugin which helps in assessing complex web apps that render the contents of
their pages dynamically. It also provides a bi-directional JavaScript bridge API which allows users
to create quick one-off BurpSuite plugin prototypes which can interact directly with the DOM and
Burp's extender API.

---

## System Requirements
BurpKit has the following system requirements:
- Oracle JDK &gt;=8u50 and &lt;9 ([Download](http://www.oracle.com/technetwork/java/javase/downloads/index.html))
- At least 4GB of RAM

---

## Installation
Installing BurpKit is simple:

1. Download the latest prebuilt release from the [GitHub releases page](https://github.com/allfro/BurpKit/releases).
2. Open BurpSuite and navigate to the `Extender` tab.
3. Under `Burp Extensions` click the `Add` button.
4. In the `Load Burp Extension` dialog, make sure that `Extension Type` is set to `Java` and click the `Select file ...` button under `Extension Details`.
5. Select the `BurpKit-<version>.jar` file and click `Next` when done.

If all goes well, you will see three additional top-level tabs appear in BurpSuite:

1.  `BurpKitty`: a courtesy browser for navigating the web within BurpSuite.
2.  `BurpScript IDE`: a lightweight integrated development environment for writing JavaScript-based BurpSuite plugins and other things.
3.  `Jython`: an integrated python interpreter console and lightweight script text editor.

---

## BurpScript
**BurpScript** enables users to write desktop-based JavaScript applications as well as BurpSuite extensions using the JavaScript scripting language. This is achieved by injecting two new objects by default into the DOM on page load:

1.  `burpKit`: provides numerous features including file system I/O support and easy JS library injection.
2.  `burpCallbacks`: the JavaScript equivalent of the `IBurpExtenderCallbacks` interface in `Java` with a few slight modifications.

Take a look at the `examples` folder for more information.
