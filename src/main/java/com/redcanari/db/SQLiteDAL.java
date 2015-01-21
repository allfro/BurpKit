package com.redcanari.db;

/**
 * Created by ndouba on 14-11-19.
 */

import java.io.File;
import java.io.IOException;
import java.sql.*;

public class SQLiteDAL {

    private static final String CREATE_TABLE_INTERNAL_DB = "CREATE TABLE IF NOT EXISTS " +
            "cache(id INTEGER PRIMARY KEY ASC, );";

    private static File databaseFile = null;
    private static SQLiteDAL instance = null;
    private static Connection c = null;
    private static Statement s = null;

    public static SQLiteDAL getInstance() throws IOException {
        databaseFile = File.createTempFile("burpsuite", "db");
        return getInstance(databaseFile.getAbsolutePath());
    }

    public static SQLiteDAL getInstance(String fileName) {
        databaseFile = new File(fileName);
        if (instance == null) {
            instance = new SQLiteDAL();
        }
        return instance;
    }

    private SQLiteDAL() {
        try {
            Class.forName("org.sqlite.JDBC");

            c = DriverManager.getConnection("jdbc:sqlite:" + databaseFile.getAbsolutePath());
            init();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private boolean init() throws SQLException {
        s = c.createStatement();
        return s.execute(CREATE_TABLE_INTERNAL_DB);
    }


}
