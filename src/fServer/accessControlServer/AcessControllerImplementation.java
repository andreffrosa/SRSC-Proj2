package fServer.accessControlServer;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

public class AcessControllerImplementation implements AcessControler {

	private static final String REGEX = " ";
	private static final int READ = 0;
	private static final int WRITE = 1;
	
	public Map<String, boolean[]> permissionsMap;

	public AcessControllerImplementation(String filePath) throws IOException {
		loadConfig(filePath);
	}

	private void loadConfig(String filePath) throws IOException {

		InputStream inputStream = new FileInputStream(filePath);
		Properties properties = new Properties();
		properties.load(inputStream);

		permissionsMap = new HashMap<String, boolean[]>(properties.size());

		for(Entry<Object, Object> entry : properties.entrySet() ) {

			String user = (String) entry.getKey();
			String privilegesString =   (String) entry.getValue();
			String[] splitedPrivileges = privilegesString.split(REGEX);
			boolean[] permissions = new boolean[2];

			if(splitedPrivileges.length == 1) //if its only deny
				Arrays.fill(permissions, false);
			else {
				if(splitedPrivileges.length > 2) 
					permissions[WRITE] = true;
				else
					permissions[WRITE] = false;
			
				permissions[READ] = true;
			}
			
			permissionsMap.put(user, permissions);
		}


	}

	@Override
	public boolean canRead(String username) {
		
		if(permissionsMap.containsKey(username))
			return permissionsMap.get(username)[READ];
		
		return false;
	}

	@Override
	public boolean canWrite(String username) {
		
		if(permissionsMap.containsKey(username))
			return permissionsMap.get(username)[WRITE];
		
		return false;
	}

}
