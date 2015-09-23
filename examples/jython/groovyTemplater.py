__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2015, The BurpKit Project'

__license__ = 'GPL'
__version__ = '1.0'

import sys
import os

# First we download our dependency, groovy-all.jar, if necessary
dependency_url = 'http://central.maven.org/maven2/org/codehaus/groovy/groovy-all/2.4.4/groovy-all-2.4.4.jar'
dependency_dir = os.path.join(os.path.expanduser('~'), '.burpkit')
dependency_file = os.path.join(dependency_dir, 'groovy.jar')

if not os.path.lexists(dependency_file):
    from urllib import URLopener

    if not os.path.lexists(dependency_dir):
        os.makedirs(dependency_dir)

    URLopener().retrieve(dependency_url, dependency_file)
    if not os.path.lexists(dependency_file):
        raise OSError('failed to download/save dependency')

sys.path.append(dependency_file)

# Next our imports. 
from groovy.text import StreamingTemplateEngine
from burp import IMessageEditorTab, IMessageEditorTabFactory, IContextMenuFactory
import java.lang.Exception
from javax.swing import JMenuItem
from java.awt.event import ActionListener
from java.util import LinkedHashMap

context = LinkedHashMap()


class TemplateTab(IMessageEditorTab):
    def __init__(self, controller, editable):
        self._editable = editable
        self._component = burp.createTextEditor()
        self._component.setEditable(editable)
        self._template = None
        self._orig_content = None
        self._engine = StreamingTemplateEngine()
        self._helpers = burp.getHelpers()

    def getMessage(self):
        self._template = self._helpers.bytesToString(self._component.getText())
        try:
            self._orig_content = self._engine.createTemplate(self._template).make(
                {'burp': burp, 'context': context}).toString()
        except java.lang.Exception, error:
            self._orig_content = error.toString()
        return self._helpers.stringToBytes(self._orig_content)

    def setMessage(self, content, isRequest):
        if isRequest:
            if self._orig_content and self._orig_content == self._helpers.bytesToString(content):
                self._component.setText(self._template)
            else:
                self._component.setText(content)

    def isEnabled(self, content, isRequest):
        return isRequest and self._editable

    def getUiComponent(self):
        return self._component.getComponent()

    def isModified(self):
        return self._component.isTextModified()

    def getTabCaption(self):
        return "Groovy Templater"

    def getSelectedData(self):
        return self._component.getSelectedText()


class TemplateTabFactory(IMessageEditorTabFactory):
    def createNewInstance(self, controller, editable):
        return TemplateTab(controller, editable)


class GroovyActionListener(ActionListener):
    def __init__(self, message, bounds):
        self._message = message
        self._bounds = bounds
        self._helpers = burp.getHelpers()
        self._engine = StreamingTemplateEngine()

    def actionPerformed(self, event):
        if self._bounds[0] == self._bounds[1]:
            return
        lower = min(self._bounds)
        upper = max(self._bounds)
        content = self._message.getRequest()
        evalContent = self._engine.createTemplate(self._helpers.bytesToString(content[lower:upper])).make(
            {'burp': burp, 'context': context}).toString()
        self._message.setRequest(content[:lower] + self._helpers.stringToBytes(evalContent) + content[upper:])


class GroovyContextMenuFactory(IContextMenuFactory):
    def createMenuItems(self, invocation):
        if invocation.getInvocationContext() != invocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            return None
        menuItem = JMenuItem("Evaluate Groovy")
        menuItem.addActionListener(
            GroovyActionListener(invocation.getSelectedMessages()[0], invocation.getSelectionBounds()))
        return [menuItem]


if 'contextFactory' in dir():
    print 'removing old context menu factory'
    burp.removeContextMenuFactory(contextFactory)

print 'registering new context menu factory'
contextFactory = GroovyContextMenuFactory()
burp.registerContextMenuFactory(contextFactory)

if 'factory' in dir():
    print 'removing old message editor tab factory'
    burp.removeMessageEditorTabFactory(factory)

print 'registering new message editor tab factory'
factory = TemplateTabFactory()
burp.registerMessageEditorTabFactory(factory)
