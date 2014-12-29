package com.redcanari.ui;

import javafx.embed.swing.SwingNode;
import javafx.scene.web.WebEngine;
import org.fife.ui.autocomplete.AutoCompletion;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import java.awt.*;


public class CodeEditor extends SwingNode {

  private WebEngine webEngine;

  public CodeEditor(WebEngine webEngine) {
    this.webEngine = webEngine;
    SwingUtilities.invokeLater(this::createFrame);
  }

  private void createFrame() {

    JPanel contentPane = new JPanel(new BorderLayout());
    RSyntaxTextArea textArea = new RSyntaxTextArea(20, 60);

    textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
    textArea.setCodeFoldingEnabled(true);

    contentPane.add(new RTextScrollPane(textArea));

    JSEngineCompletionProvider provider = new JSEngineCompletionProvider(webEngine);

    AutoCompletion autoCompletion = new AutoCompletion(provider);
//    autoCompletion.setAutoActivationEnabled(true);
//    autoCompletion.setAutoActivationDelay(100);
    autoCompletion.install(textArea);

    setContent(contentPane);
  }



}