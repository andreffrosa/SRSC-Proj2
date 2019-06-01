package utility;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

public class IO {

	public static Properties loadProperties(String path) throws IOException {
		InputStream inputStream = new FileInputStream(path);
		Properties properties = new Properties();
		properties.load(inputStream);
		return properties;
	}
	
	public static String resolvePath(String current_path, String path) {

		String folders[] = path.split("/");
		
		if(path.endsWith("/"))
			folders[folders.length-1] += "/";

		String final_path = "";
		Path final_p;
		if(path.startsWith("/") )
			final_p = Paths.get("/");
		else
			final_p = Paths.get(current_path);
		
		for (String current_folder : folders) {
			if (current_folder.equals("..")) {
				final_path = final_p.getParent().toString();
				final_p = Paths.get(final_path);
				System.out.println("1" + final_path);
			} else if (current_folder.equals(".")) {
				final_path = final_p.toString();
				final_p = Paths.get(final_path);
				System.out.println("2" + final_path);
			} else {
				final_path = final_p.resolve(current_folder).toString();
				final_p = Paths.get(final_path);
				System.out.println("3" + final_path);
			}
		}
		if(path.endsWith("/"))
			return final_path + "/";
		else
			return final_path;
	}

}
