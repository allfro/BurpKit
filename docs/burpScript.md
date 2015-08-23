# Overview
BurpScript is a JavaScript langauge extension that provides additional language features within WebKit's JS engine such as:

*  Filesystem I/O - provides support for writing to and reading from files.
*  Script injection - provides an easy interface for injecting libraries such as JQuery or other third-party libraries.
*  BurpExtender - exposes the BurpSuite interface to the JS engine so that you can write your own BurpSuite plugins using JavaScript.

BurpScript can be used to perform a variety of tasks ranging from OSINT automation scripts to full-fledged BurpSuite
extensions. Take a look at the [examples](https://github.com/allfro/BurpKit/tree/master/examples) folder in the code repository to see how BurpKit can be leveraged.