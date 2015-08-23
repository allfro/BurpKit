# Welcome to BurpKit

Welcome to the next generation of web application penetration testing - using WebKit to own the web.
BurpKit is a BurpSuite plugin which helps in assessing complex web apps that render the contents of
their pages dynamically. As part of its rich feature set, BurpKit  provides a bi-directional
JavaScript bridge API which allows users to quickly create BurpSuite plugins  which can interact 
directly with the DOM and Burp's extender API at the same time. This permits BurpSuite plugin
developers to run their web application testing logic directly within the DOM itself whilst taking
advantage of BurpSuite's other features as well!

For example, imagine building an intruder payload generator that dynamically generates a word list
while crawling a Web 2.0 web application such as Twitter. Or maybe using the BurpScript extensions
to scrape web pages and save those results to a file. What about building a better web spider that 
can render AJAX-based pages and send discovered content to the active scanner? All this can be done
with BurpKit and more! 

---

# Getting Started

## System Requirements
BurpKit has the following system requirements:

*  Oracle JDK &gt;=8u50 and &lt;9 ([Download](http://www.oracle.com/technetwork/java/javase/downloads/index.html))
*  At least 4GB of RAM


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

## Compiling BurpKit
BurpKit is distributed as an [IntelliJ IDEA](https://www.jetbrains.com/idea/) project. Once the project is opened in IntelliJ, compilation should be trivial. The JAR file can be built using the `Build Artifacts...` menu item under the `Build` menu. The compiled output will appear under the `out` directory.


## Known Issues
The following sections detail known issues that have been discovered within BurpKit and possible workarounds.


### No Upstream Proxy Support
Upstream proxies set within BurpSuite's `Options` tab are currently not supported as there exists no way to monitor BurpSuite setting modifications. Therefore, upstream proxies will have to be configured at the system level or via the Java command line arguments. BurpKit may leverage BurpSuite's internal request framework in future releases.


### Blank Tabs
Unhandled exceptions within the JavaFX event loop may trigger this condition. Currently, BurpKit-v1.01-pre attempts to resolve this issue. If you are still experiencing this issue, please run BurpSuite from the command line (e.g. `java -jar burpsuite_<version>.jar -Xmx4g`)  and [open a GitHub issue](https://github.com/allfro/BurpKit/issues/new) with the following details:

1.  OS and system details (please include RAM size);
2.  Console output, if any;
2.  Java version (`java -version`); and
3.  BurpSuite runtime arguments, if applicable.

