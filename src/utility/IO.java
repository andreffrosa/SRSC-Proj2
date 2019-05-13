package utility;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class IO {

	public static Properties loadProperties(String path) throws IOException {
		InputStream inputStream = new FileInputStream(path);
		Properties properties = new Properties();
		properties.load(inputStream);
		return properties;
	}
	
}
