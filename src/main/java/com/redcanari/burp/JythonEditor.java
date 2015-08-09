package com.redcanari.burp;

import com.redcanari.ui.JConsole;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;

/**
 * Created by ndouba on 15-07-08.
 */
public class JythonEditor {
    private JPanel root;
    private JConsole console;
    private JButton runScriptButton;
    private JButton clearConsoleButton;
    private JEditorPane scriptTextPane;
    private JButton saveScriptButton;
    private JButton loadScriptButton;

    public JythonEditor() {
        runScriptButton.addActionListener(e -> console.runScript(scriptTextPane.getText()));
        clearConsoleButton.addActionListener(e -> console.clear());
        saveScriptButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showSaveDialog(root) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                try {
                    Files.write(file.toPath(), scriptTextPane.getText().getBytes(),
                            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        });

        loadScriptButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(root) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                try {
                    scriptTextPane.setText(new String(Files.readAllBytes(file.toPath())));
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        });
    }

    public Component getRoot() {
        return root;
    }
}
