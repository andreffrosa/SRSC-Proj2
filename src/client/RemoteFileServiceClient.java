package client;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.ws.rs.core.Response.Status;

import client.exception.FileNotFoundException;
import client.exception.LogginRequieredException;
import client.exception.UnautorizedException;
import fServer.authServer.AuthenticationClient;
import fServer.authServer.DeniedAccessException;
import fServer.authServer.WrongChallengeAnswerException;
import fServer.mainDispatcher.RemoteFileService;
import rest.RestResponse;
import rest.client.mySecureRestClient;
import ssl.CustomSSLSocketFactory;
import token.ExpiredTokenException;
import token.auth.AuthenticationToken;
import utility.Cryptography;
import utility.LoginUtility;
import utility.RequestHandler;

public class RemoteFileServiceClient{

	private static final int MAX_TRIES = 3;
	private String location;
	private mySecureRestClient client;
	private AuthenticationToken authToken;
	private LoginUtility login_util; 

	public RemoteFileServiceClient(KeyStore ks, String ks_password, KeyStore ts, String location, LoginUtility login_util)
			throws UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, UnknownHostException, CertificateException, IOException {
		this.location = location;
		this.client = new mySecureRestClient(new CustomSSLSocketFactory(ks, ks_password, ts), location);
		this.authToken = null;
		this.login_util = login_util;
	}

	private <K, T> T processRequest(RequestHandler<String, T> requestHandler) {

		for (int current_try = 0; current_try < MAX_TRIES; current_try++) {
			try {
				return requestHandler.execute(location);
			} catch (Exception e) {
				e.printStackTrace();
				if (e.getMessage().contains("java.net.ConnectException")
						|| e.getMessage().contains("java.net.SocketTimeoutException")) {
					System.out.println(String.format("Error contacting server %s .... retry: %d", location, current_try));
				} 
			}
		}

		throw new RuntimeException("Aborted request! Too many tries...");
	}

	public boolean login(String username, String password) throws ExpiredTokenException, WrongChallengeAnswerException, DeniedAccessException {

		try {

			authToken = AuthenticationClient.login(client, RemoteFileService.PATH, username, password, login_util);

			return true;

		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException
				| InvalidAlgorithmParameterException | ShortBufferException | IllegalBlockSizeException
				| BadPaddingException | NoSuchPaddingException | InvalidKeySpecException | IOException e) {

			e.printStackTrace();

		} catch(ExpiredTokenException | WrongChallengeAnswerException | DeniedAccessException e) {
			throw e;
		}
		return false;
	}

	public boolean logout() {
		if(this.authToken!=null) {
			this.authToken = null;
			return true;
		} 

		return false;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(String username, String path)  throws LogginRequieredException, UnautorizedException, FileNotFoundException {

		String nonce = "" + Cryptography.genNonce(login_util.getRandom());

		RestResponse response = processRequest((location) -> {
			return client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addHeader("Access", null)
					.addHeader("nonce", nonce)
					.addPathParam("ls")
					.addPathParam(username)
					.addPathParam(path)
					.get();
		});
		
		if (response.getStatusCode() == Status.OK.getStatusCode()) { 
			return (List<String>) response.getEntity(List.class);			
		}else if(response.getStatusCode() == Status.UNAUTHORIZED.getStatusCode()) {
			throw new LogginRequieredException("Invalid Loggin.\n");
		}else if(response.getStatusCode() == Status.FORBIDDEN.getStatusCode() ) {
			throw new UnautorizedException("Access denied.\n");
		}else if(response.getStatusCode() == Status.NOT_FOUND.getStatusCode()) {
			throw new FileNotFoundException("Folder not foud.\n");
		}else
			throw new RuntimeException("ls: " + response.getStatusCode());
	}

	public boolean mkdir(String username, String path) throws LogginRequieredException, UnautorizedException {
		String nonce = "" + Cryptography.genNonce(login_util.getRandom());
		RestResponse response = processRequest((location) -> {
			return client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addHeader("Access", null)
					.addHeader("nonce", nonce)
					.addPathParam("mkdir")
					.addPathParam(username)
					.addPathParam(path)
					.post(null);
		});
		
		if (response.getStatusCode() == Status.OK.getStatusCode()) {
			return (boolean) response.getEntity(boolean.class);
		}else if(response.getStatusCode() == Status.UNAUTHORIZED.getStatusCode()) {
			throw new LogginRequieredException("Invalid Loggin.\n");
		}else if(response.getStatusCode() == Status.FORBIDDEN.getStatusCode() ) {
			throw new UnautorizedException("Access denied.\n");
		} else
			throw new RuntimeException("mkdir: " + response.getStatusCode());
	}

	public boolean upload(String username, String path, byte[] data) throws LogginRequieredException, UnautorizedException {
		String nonce = "" + Cryptography.genNonce(login_util.getRandom());
		RestResponse response = processRequest((location) -> {
			return client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addHeader("Access", null)
					.addHeader("nonce", nonce)
					.addPathParam("put")
					.addPathParam(username)
					.addPathParam(path)
					.put(data);
		});
		
		if (response.getStatusCode() == Status.OK.getStatusCode()) {
			return (boolean) response.getEntity(boolean.class);
		}else if(response.getStatusCode() == Status.UNAUTHORIZED.getStatusCode()) {
			throw new LogginRequieredException("Invalid Loggin.\n");
		}else if(response.getStatusCode() == Status.FORBIDDEN.getStatusCode() ) {
			throw new UnautorizedException("Access denied.\n");			
		} else
			throw new RuntimeException("put: " + response.getStatusCode());
	}

	public byte[] download(String username, String path) throws LogginRequieredException, UnautorizedException, FileNotFoundException {
		String nonce = "" + Cryptography.genNonce(login_util.getRandom());
		RestResponse response = processRequest((location) -> {
			return client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addHeader("Access", null)
					.addHeader("nonce", nonce)
					.addPathParam("get")
					.addPathParam(username)
					.addPathParam(path)
					.get();

		});
	
		if (response.getStatusCode() == Status.OK.getStatusCode()) {
			return (byte[]) response.getEntity(byte[].class);
		}else if(response.getStatusCode() == Status.UNAUTHORIZED.getStatusCode()) {
			throw new LogginRequieredException("Invalid Loggin.\n");
		}else if(response.getStatusCode() == Status.FORBIDDEN.getStatusCode() ) {
			throw new UnautorizedException("Access denied.\n");
		}else if(response.getStatusCode() == Status.NOT_FOUND.getStatusCode()) {
			throw new FileNotFoundException("File Not Found.\n");
		} else
			throw new RuntimeException("get: " + response.getStatusCode());
	}

	public boolean copy(String username, String origin, String dest) throws LogginRequieredException, UnautorizedException, FileNotFoundException {
		String nonce = "" + Cryptography.genNonce(login_util.getRandom());
		RestResponse response = processRequest((location) -> {
			return client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addHeader("Access", null)
					.addHeader("nonce", nonce)
					.addPathParam("cp")
					.addPathParam(username)
					.addPathParam(origin)
					.addPathParam(dest)
					.put(null);
		});
	
		if (response.getStatusCode() == Status.OK.getStatusCode()) {
			return (boolean) response.getEntity(boolean.class);
		}else if(response.getStatusCode() == Status.UNAUTHORIZED.getStatusCode()) {
			throw new LogginRequieredException("Invalid Loggin.\n");
		}else if(response.getStatusCode() == Status.FORBIDDEN.getStatusCode() ) {
			throw new UnautorizedException("Access denied.\n");
		}else if(response.getStatusCode() == Status.NOT_FOUND.getStatusCode()) {
			throw new FileNotFoundException("File Not Found.\n");
		} else 
			throw new RuntimeException("cp: " + response.getStatusCode());
	}
	

	public boolean remove(String username, String path) throws LogginRequieredException, UnautorizedException, FileNotFoundException {
		String nonce = "" + Cryptography.genNonce(login_util.getRandom());
		RestResponse response = processRequest((location) -> {
			return client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addHeader("Access", null)
					.addHeader("nonce", nonce)
					.addPathParam("rm")
					.addPathParam(username)
					.addPathParam(path)
					.delete(null);
		});
		
		if (response.getStatusCode() == 200) {
			return (boolean) response.getEntity(boolean.class);
		}else if(response.getStatusCode() == Status.UNAUTHORIZED.getStatusCode()) {
			throw new LogginRequieredException("Invalid Loggin.\n");
		}else if(response.getStatusCode() == Status.FORBIDDEN.getStatusCode() ) {
			throw new UnautorizedException("Access denied.\n");
		}else if(response.getStatusCode() == Status.NOT_FOUND.getStatusCode()) {
			throw new FileNotFoundException("File not found.");
		} else
			throw new RuntimeException("rm: " + response.getStatusCode());
	}

	public boolean removeDirectory(String username, String path) throws LogginRequieredException, UnautorizedException, FileNotFoundException {
		String nonce = "" + Cryptography.genNonce(login_util.getRandom());
		RestResponse response = processRequest((location) -> {
			return client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addHeader("Access", null)
					.addHeader("nonce", nonce)
					.addPathParam("rmdir")
					.addPathParam(username)
					.addPathParam(path)
					.delete(null);
		});
		
		if (response.getStatusCode() == 200) {
			return (boolean) response.getEntity(boolean.class);
		}else if(response.getStatusCode() == Status.UNAUTHORIZED.getStatusCode()) {
			throw new LogginRequieredException("Invalid Loggin.\n");
		}else if(response.getStatusCode() == Status.FORBIDDEN.getStatusCode() ) {
			throw new UnautorizedException("Access denied.\n");
		}else if(response.getStatusCode() == Status.NOT_FOUND.getStatusCode()) {
			throw new FileNotFoundException("Directory not found.\n");
		} else
			throw new RuntimeException("rmdir: " + response.getStatusCode());
	}

	public String getFileMetadata(String username, String path) throws LogginRequieredException, UnautorizedException, FileNotFoundException {
		String nonce = "" + Cryptography.genNonce(login_util.getRandom());
		RestResponse response = processRequest((location) -> {
			return client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addHeader("Access", null)
					.addHeader("nonce", nonce)
					.addPathParam("file")
					.addPathParam(username)
					.addPathParam(path)
					.get();
		});	
		
		if (response.getStatusCode() == 200) {
			return (String) response.getEntity(String.class);
		}else if(response.getStatusCode() == Status.UNAUTHORIZED.getStatusCode()) {
			throw new LogginRequieredException("Invalid Loggin.\n");
		}else if(response.getStatusCode() == Status.FORBIDDEN.getStatusCode() ) {
			throw new UnautorizedException("Access denied.\n");
		}else if(response.getStatusCode() == Status.NOT_FOUND.getStatusCode()) {
			throw new FileNotFoundException("File not found.\n");
		} else
			throw new RuntimeException("file: " + response.getStatusCode());
	}

	public AuthenticationToken getToken() {
		return authToken;
	}
}
