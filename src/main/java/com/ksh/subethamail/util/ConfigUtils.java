package com.ksh.subethamail.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.FileNotFoundException;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfigUtils {
    private static final Logger log = LoggerFactory.getLogger(ConfigUtils.class);

    public static String parseArgs(String[] args) {
        for (int i = 0; i < args.length - 1; i++) {
            if ("-config".equals(args[i])) {
                log.info("Using config file: {}", args[i + 1]);
                return args[i + 1];
            }
        }
        return null;
    }

    public static Properties loadConfig(String fileName) throws IOException {
        Properties props = new Properties();
        try (InputStream input = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName)) {
            if (input == null) {
                throw new FileNotFoundException("Properties file not found in classpath: " + fileName);
            }
            props.load(input);
        }
        return props;
    }
}
