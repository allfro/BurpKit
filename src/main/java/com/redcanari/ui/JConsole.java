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

package com.redcanari.ui;

import burp.BurpExtender;
import org.python.core.Py;
import org.python.core.PyException;
import org.python.util.InteractiveConsole;

import javax.swing.*;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

/**
 * Created by ndouba on 15-07-07.
 */
public class JConsole extends JTextArea {

    final InteractiveConsole interpreter;
    private int editableStart = 0;
    private final String PS1;
    private final String PS2;
    private PythonWorker worker;
    private boolean isClearing = false;

    public InteractiveConsole getInterpreter() {
        return interpreter;
    }

    public void clear() {
        isClearing = true;
        setEditable(false);
        setText(PS1);
        editableStart = getDocument().getLength();
        isClearing = false;
        setEditable(true);
    }

    public void runScript(String script) {
        setEditable(false);
        append("\n");
        new PythonScriptWorker(script).execute();
    }

    private class PythonScriptWorker extends SwingWorker<Void, Void> {

        private final String source;

        public PythonScriptWorker(String source) {
            this.source = source;
        }

        @Override
        protected Void doInBackground() throws Exception {
            try
            {
                interpreter.exec(source);
            }
            catch (PyException e)
            {
                // prints out the python error message to the console
                e.printStackTrace();
            }
            return null;
        }

        @Override
        protected void done() {
            SwingUtilities.invokeLater(() -> {
                append(PS1);
                editableStart = getDocument().getLength();
                setEditable(true);
            });
        }
    }

    private class CommandHistory {
        final List<String> commands = new ArrayList<>();
        int current = -1;

        public synchronized void add(String command) {
            commands.add(0, command);
            current = 0;
        }

        public String previous() {
            if (current == 0)
                return "";
            return commands.get(current--);
        }

        public String next() {
            if (current == commands.size() - 1)
                return commands.get(current);
            return commands.get(current++);
        }
    }

    CommandHistory history = new CommandHistory();

    private class PythonWorker extends SwingWorker<Boolean, Void> {

        private final String source;
        private final boolean addToHistory;

        public PythonWorker(String source) {
            this(source, true);
        }

        public PythonWorker(String source, boolean addToHistory) {
            this.source = source.replace("\n", "");
            this.addToHistory = addToHistory;
        }

        @Override
        protected Boolean doInBackground() throws Exception {
            try
            {
                if (addToHistory) {
                    history.add(source);
                }
                return interpreter.push(source);
            }
            catch (PyException e)
            {
                // prints out the python error message to the console
                e.printStackTrace();
            }
            return false;
        }

        @Override
        protected void done() {
            SwingUtilities.invokeLater(() -> {
                try {
                    append((get() && !isCancelled())? PS2 : PS1);
                    editableStart = getDocument().getLength();
                    setCaretPosition(editableStart);
                    setEditable(true);
                } catch (InterruptedException | ExecutionException e) {
                    e.printStackTrace();
                }
            });
        }
    }

    public JConsole() {
        super();
        PS1 = Py.getSystemState().ps1.toString();
        PS2 = Py.getSystemState().ps2.toString();

        setFont(Font.getFont(Font.MONOSPACED));
        setAutoscrolls(true);
        setLineWrap(true);

        interpreter = new InteractiveConsole();
        interpreter.set("burp", BurpExtender.getBurpExtenderCallbacks());

        interpreter.setErr(new PrintWriter(System.err) {
            @Override
            public void write(String s) {
                SwingUtilities.invokeLater(() -> JConsole.this.append(s));
            }
        });
        interpreter.setOut(new PrintWriter(System.out) {
            @Override
            public void write(String s) {
                SwingUtilities.invokeLater(() -> JConsole.this.append(s));
            }
        });

        ((AbstractDocument)getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override
            public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {
                if (offset >= editableStart || isClearing)
                    super.remove(fb, offset, length);
            }

            @Override
            public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs) throws BadLocationException {
                if (offset >= editableStart || isClearing)
                    super.replace(fb, offset, length, text, attrs);
            }

            @Override
            public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr) throws BadLocationException {
                if (offset >= editableStart || isClearing)
                    super.insertString(fb, offset, string, attr);
            }
        });

        addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyChar() == '\n') {
                    try {
                        setEditable(false);
                        append("\n");
                        worker = new PythonWorker(getText().substring(editableStart));
                        worker.execute();
                    } catch (Exception e1) {
                        e1.printStackTrace();
                    }
                    e.consume();
                } else if (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_C) {
                    if (!worker.isDone()) {
                        worker.cancel(true);
                        interpreter.resetbuffer();
                    }
                    e.consume();
                } else if (e.getKeyCode() == KeyEvent.VK_UP) {
                    replaceRange(history.next(), editableStart, getDocument().getLength());
                    e.consume();
                } else if (e.getKeyCode() == KeyEvent.VK_DOWN) {
                    replaceRange(history.previous(), editableStart, getDocument().getLength());
                    e.consume();
                } else if (e.getKeyCode() == KeyEvent.VK_HOME) {
                    SwingUtilities.invokeLater(() -> setCaretPosition(editableStart));
                    e.consume();
                } else if (e.getKeyCode() == KeyEvent.VK_LEFT) {
                    if (getCaretPosition() <= editableStart)
                        e.consume();
                } else if (e.getKeyCode() == KeyEvent.VK_TAB) {
                    String text = getText().substring(editableStart);
                    if (text.matches("^[^\\(\\)]+\\.$")) {
                        setEditable(false);
                        append("\n");
                        new PythonWorker(String.format("print ' '.join(dir(%s))", text.substring(0, text.length()-1)), false).execute();
                        e.consume();
                    }
                }
            }
        });

        new PythonWorker("print \"\"\"" + InteractiveConsole.getDefaultBanner() + "\"\"\"", false).execute();
    }


    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("test");
            frame.add(new JScrollPane(new JConsole()));
            frame.setSize(400, 400);
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setVisible(true);
        });
    }
}
