package fServer.accessControlServer;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import fServer.authServer.AuthenticationToken;
import fServer.authServer.TokenVerifier;

public class AcessControllerImplementation implements AcessControler {

	private static final String REGEX = " ";
	private static final int READ_POS = 0;
	private static final int WRITE_POS = 1;
	
	private Map<String, boolean[]> permissionsMap;
	private TokenVerifier tokenVerifier;

	public AcessControllerImplementation(String filePath, TokenVerifier tokenVerifier) throws IOException {
		loadConfig(filePath);
		this.tokenVerifier = tokenVerifier;
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
					permissions[WRITE_POS] = true;
				else
					permissions[WRITE_POS] = false;
			
				permissions[READ_POS] = true;
			}
			
			permissionsMap.put(user, permissions);
		}
	}
		
	private boolean canRead(String username) {
		
		System.out.print("Recieved read access verification for user " + username + ". Result: ");
		
		if(permissionsMap.containsKey(username)) 
			if(permissionsMap.get(username)[READ_POS]) {
				System.out.println("granted");
				return true;
			}
			
		System.out.println("denied");
		return false;
	}

	private boolean canWrite(String username) {
		
		System.out.print("Recieved write access verification for user " + username + ". Result: ");
		
		if(permissionsMap.containsKey(username))
			if(permissionsMap.get(username)[WRITE_POS]) {
				System.out.println("granted");				
				return true;
			}
		
		System.out.println("denied");		
		return false;
	}

	@Override
	public boolean hasAccess(String token, String opeartion, String username) throws InvalidKeyException, SignatureException, IOException {
		
		AuthenticationToken auth = AuthenticationToken.parseToken(token);
		if(!tokenVerifier.validateToken(System.currentTimeMillis(), auth)) {
			System.out.println("User " + username + " presented invalid token");
			return false;
		}
		
		if(opeartion.equals(AcessControler.WRITE_ACCESS_REQUEST))
			return canWrite(username);
		else
			return canRead(username);
		
	}

}
