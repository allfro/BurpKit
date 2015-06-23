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

package com.redcanari.db;

import com.redcanari.net.http.HttpMockResponse;
import com.redcanari.util.HttpUtils;

import java.io.*;
import java.net.URL;
import java.sql.*;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Nadeem Douba
 * @version 1.0
 * @since 2014-11-19.
 */
public class HttpMockResponseSQLCache {

    private static final String CREATE_TABLE_INTERNAL_DB = "CREATE TABLE IF NOT EXISTS " +
            "cache(id INTEGER PRIMARY KEY ASC, digest TEXT, url TEXT, " +
            "object BLOB, UNIQUE(digest, url) ON CONFLICT REPLACE);";
    private static final String INSERT_INTO_CACHE = "INSERT INTO cache(digest, url, object) VALUES(?, ?, ?)";
    private static final String SELECT_FROM_CACHE = "SELECT object FROM cache WHERE digest=? and url=?;";
    private static final String SELECT_IF_EXISTS = "SELECT COUNT(*) FROM cache WHERE digest=? and url=?;";

    private static final Set<String> firstLevelCache = new HashSet<>();


    private static File databaseFile = null;
    private static HttpMockResponseSQLCache instance = null;
    private static Connection connection = null;

    public static synchronized HttpMockResponseSQLCache getInstance() {
        if (instance == null) {
            try {
                databaseFile = File.createTempFile("burpsuite", "db");
                databaseFile.deleteOnExit();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return getInstance(databaseFile.getAbsolutePath());
        }
        return instance;
    }

    public static synchronized HttpMockResponseSQLCache getInstance(String fileName) {
        if (instance == null) {
            databaseFile = new File(fileName);
            instance = new HttpMockResponseSQLCache();
        }
        return instance;
    }

    private HttpMockResponseSQLCache() {
        try {
            Class.forName("org.sqlite.JDBC");

            connection = DriverManager.getConnection("jdbc:sqlite:" + databaseFile.getAbsolutePath());
            init();
        } catch (ClassNotFoundException | SQLException e) {
            e.printStackTrace();
        }
    }

    private boolean init() throws SQLException {
        Statement statement = connection.createStatement();
        boolean result = statement.execute(CREATE_TABLE_INTERNAL_DB);
        statement.close();
        return result;
    }

    public synchronized HttpMockResponse get(String digest, URL url) {
        try {
            PreparedStatement preparedStatement = connection.prepareStatement(SELECT_FROM_CACHE);

            preparedStatement.setString(1, digest);
            preparedStatement.setString(2, HttpUtils.normalizeUrl(url));

            ResultSet resultSet = preparedStatement.executeQuery();
            byte[] buf = resultSet.getBytes(1);

            resultSet.close();
            preparedStatement.close();

            if (buf != null) {
                ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(buf));
                return (HttpMockResponse) objectInputStream.readObject();
            }
        } catch (ClassNotFoundException | SQLException | IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public synchronized boolean containsKey(String digest, URL url) {
//        boolean result = false;
        String normalizedURL = HttpUtils.normalizeUrl(url);
//        try {
//            PreparedStatement preparedStatement = connection.prepareStatement(SELECT_IF_EXISTS);
//            preparedStatement.setString(1, digest);
//            preparedStatement.setString(2, normalizedURL);
//
//            ResultSet resultSet = preparedStatement.executeQuery();
//            result = resultSet.getInt(1) > 0;
//
//            resultSet.close();
//            preparedStatement.close();
//
//
//
//            return result;
//        } catch (SQLException e) {
//            e.printStackTrace();
//        }
//        return result;
        return firstLevelCache.contains(digest + ":" + normalizedURL);
    }

    public synchronized void put(String digest, URL url, HttpMockResponse value) {
        String normalizedURL = HttpUtils.normalizeUrl(url);
        try {
            if (containsKey(digest, url))
                return;

            PreparedStatement preparedStatement = connection.prepareStatement(INSERT_INTO_CACHE);

            preparedStatement.setString(1, digest);
            preparedStatement.setString(2, normalizedURL);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(value);
            preparedStatement.setBytes(3, byteArrayOutputStream.toByteArray());

            preparedStatement.executeUpdate();

            preparedStatement.close();

            firstLevelCache.add(digest + ":" + normalizedURL);
        } catch (SQLException | IOException e) {
            e.printStackTrace();
        }
    }

}
