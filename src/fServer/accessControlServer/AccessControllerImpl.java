package fServer.accessControlServer;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.ws.rs.core.Response.Status;

import rest.RestResponse;
import token.TokenVerifier;
import token.access.AccessToken;
import token.access.AccessTokenIssuer;
import token.auth.AuthenticationToken;

public class AccessControllerImpl implements AccessControler {

	private static final String REGEX = " ";
	private static final int READ_POS = 0;
	private static final int WRITE_POS = 1;

	private Map<String, boolean[]> permissionsMap;
	private TokenVerifier tokenVerifier;
	private AccessTokenIssuer tokenIssuer;

	public AccessControllerImpl(String filePath, TokenVerifier tokenVerifier, AccessTokenIssuer tokenIssuer) throws IOException {
		loadConfig(filePath);
		this.tokenVerifier = tokenVerifier;
		this.tokenIssuer = tokenIssuer;
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
	public synchronized RestResponse hasAccess(String auth_token, String username, String operation_type, String params, long nonce) throws InvalidKeyException, SignatureException, IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {

		AuthenticationToken auth = AuthenticationToken.parseToken(auth_token, null);
		if(!tokenVerifier.validateToken(System.currentTimeMillis(), auth)) {
			System.out.println( username + " presented invalid authentication token!");
			return new RestResponse("1.0", Status.FORBIDDEN.getStatusCode(), "Forbidden", "Invalid Authentication Token.");
		}

		boolean result = false;

		if(operation_type.equals(AccessControler.WRITE_ACCESS_REQUEST)) {
			result = canWrite(username);
		}else
			result = canRead(username);

		System.out.println( username + " has access to " + operation_type  + "? " + (result ? "granted" : "denied"));

		if(result) {
			AccessToken access_token = tokenIssuer.newToken(params, operation_type, nonce);
			return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", access_token.getBase64());
		} else
			return new RestResponse("1.0",Status.FORBIDDEN.getStatusCode(), "Forbidden", String.format("%s has no permissions to %s\n.", username, operation_type));
	}

}
