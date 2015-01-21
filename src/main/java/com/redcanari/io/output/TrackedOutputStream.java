package com.redcanari.io.output;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by ndouba on 14-11-21.
 */
public class TrackedOutputStream extends OutputStream {

    OutputStream outputStream = null;
    ByteArrayOutputStream byteArrayOutputStream = null;
    Instant startTime = null;
    Instant endTime = null;

    private static final Logger logger = Logger.getLogger(TrackedOutputStream.class.getName());

    public TrackedOutputStream(OutputStream outputStream) {
        this.outputStream = outputStream;
        this.byteArrayOutputStream = new ByteArrayOutputStream();
    }

    private void startTimer() {
        if (startTime == null) {
            startTime = Instant.now();
            logger.log(Level.INFO, "Started write timer.");
            System.out.println("Started write timer.");
        }
    }

    private void stopTimer() {
        if (endTime == null) {
            endTime = Instant.now();
//            logger.log(Level.INFO, "Stopped write timer. Delta = {0}", getTiming());
            System.out.println("Stopped write timer. Delta = " + getTiming());
        }
    }

    @Override
    public void write(byte[] b) throws IOException {
        startTimer();

        outputStream.write(b);
        byteArrayOutputStream.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        startTimer();

        outputStream.write(b, off, len);
        byteArrayOutputStream.write(b, off, len);
    }

    @Override
    public void flush() throws IOException {
        outputStream.flush();
        byteArrayOutputStream.flush();
    }

    @Override
    public void close() throws IOException {
        stopTimer();

        outputStream.close();
        byteArrayOutputStream.close();
    }

    @Override
    public void write(int b) throws IOException {
        startTimer();

        byteArrayOutputStream.write(b);
        outputStream.write(b);
    }

    public long getTiming() {
        return endTime.toEpochMilli() - startTime.toEpochMilli();
    }

    public byte[] getBytes() {
        return this.byteArrayOutputStream.toByteArray();
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }
}
