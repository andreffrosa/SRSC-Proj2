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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.ws.rs.core.Response.Status;

import java.util.Properties;

import fServer.authServer.AuthenticationToken;
import fServer.authServer.TokenVerifier;
import rest.RestResponse;

public class AccessControllerImplementation implements AccessControler {

	private static final String REGEX = " ";
	private static final int READ_POS = 0;
	private static final int WRITE_POS = 1;

	private Map<String, boolean[]> permissionsMap;
	private TokenVerifier tokenVerifier;

	public AccessControllerImplementation(String filePath, TokenVerifier tokenVerifier) throws IOException {
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

	private synchronized boolean canRead(String username) {

		if(permissionsMap.containsKey(username)) 
			if(permissionsMap.get(username)[READ_POS]) {
				return true;
			}

		return false;
	}

	private synchronized boolean canWrite(String username) {

		if(permissionsMap.containsKey(username))
			if(permissionsMap.get(username)[WRITE_POS]) {		
				return true;
			}

		return false;
	}

	@Override
	public synchronized RestResponse hasAccess(String token, String operation, String username) throws InvalidKeyException, SignatureException, IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {

		AuthenticationToken auth = AuthenticationToken.parseToken(token, null);
		if(!tokenVerifier.validateToken(System.currentTimeMillis(), auth)) {
			System.out.println("User " + username + " presented invalid token");
			return new RestResponse("1.0", Status.FORBIDDEN.getStatusCode(), "Forbidden", "Invalid Token.");
		}

		boolean result = false;

		if(operation.equals(AccessControler.WRITE_ACCESS_REQUEST)) {
			result = canWrite(username);
		}else
			result = canRead(username);

		System.out.println( username + " has access to " + operation  + "? " + (result ? "granted" : "denied"));

		if(result)
			return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", true);
		else
			return new RestResponse("1.0",Status.FORBIDDEN.getStatusCode(), "Forbidden", "Permission Denied");
	}

}
