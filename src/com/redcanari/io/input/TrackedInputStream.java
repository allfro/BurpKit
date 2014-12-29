package com.redcanari.io.input;

import java.io.*;
import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by ndouba on 14-11-21.
 */
public class TrackedInputStream extends InputStream {

    InputStream inputStream = null;
    ByteArrayOutputStream byteArrayOutputStream = null;
    Instant startTime = null;
    Instant endTime = null;
    private static final Logger logger = Logger.getLogger(TrackedInputStream.class.getName());

    public TrackedInputStream(InputStream inputStream) {
        this.inputStream = inputStream;
        this.byteArrayOutputStream = new ByteArrayOutputStream();
    }

    private void startTimer() {
        if (startTime == null) {
            startTime = Instant.now();
            logger.log(Level.INFO, "Started read timer.");
            System.out.println("Started read timer.");
        }
    }

    private void stopTimer() {
        if (endTime == null) {
            endTime = Instant.now();
//            logger.log(Level.INFO, "Stopped read timer. Delta = {0}", getTiming());
            System.out.println("Stopped read timer. Delta = " + getTiming());
        }
    }

    @Override
    public int read() throws IOException {
        startTimer();

        int data = inputStream.read();
        byteArrayOutputStream.write(data);
        return data;
    }

    @Override
    public int read(byte[] b) throws IOException {
        startTimer();

        int size = inputStream.read(b);
        byteArrayOutputStream.write(b);
        return size;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        startTimer();

        int size = inputStream.read(b, off, len);
        byteArrayOutputStream.write(b, off, len);
        return size;
    }

    @Override
    public long skip(long n) throws IOException {
        startTimer();

        byte [] skippedData = new byte[(int)n];
        int size = inputStream.read(skippedData);
        byteArrayOutputStream.write(skippedData, 0, size);
        return size;
    }

    @Override
    public int available() throws IOException {
        return inputStream.available();
    }

    @Override
    public void close() throws IOException {
        stopTimer();
        inputStream.close();
    }

    @Override
    public synchronized void mark(int readLimit) {
        inputStream.mark(readLimit);
    }

    @Override
    public synchronized void reset() throws IOException {
        inputStream.reset();
    }

    @Override
    public boolean markSupported() {
        return inputStream.markSupported();
    }

    public long getTiming() {
        return endTime.toEpochMilli() - startTime.toEpochMilli();
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }

    public byte[] getBytes() {
        return byteArrayOutputStream.toByteArray();
    }

}
