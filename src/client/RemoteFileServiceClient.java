package client;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

import fServer.authServer.AuthenticationClient;
import fServer.authServer.AuthenticationToken;
import fServer.authServer.DeniedAccessException;
import fServer.authServer.ExpiredTokenException;
import fServer.authServer.WrongChallengeAnswerException;
import fServer.mainDispatcher.RemoteFileService;
import rest.RestResponse;
import rest.client.mySecureRestClient;
import ssl.CustomSSLSocketFactory;
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
				//if (e.getMessage().contains("java.net.ConnectException")
				//		|| e.getMessage().contains("java.net.SocketTimeoutException")) {
				System.out.println(String.format("Error contacting server %s .... retry: %d", location, current_try));
				/*} else {
					e.printStackTrace();
					throw new RuntimeException(e.getMessage());
				}*/
			}
		}

		throw new RuntimeException("Aborted request! Too many tries...");
	}

	public boolean login(String username, String password) throws ExpiredTokenException, WrongChallengeAnswerException, DeniedAccessException {

		try {
			authToken = AuthenticationClient.login(client, RemoteFileService.PATH, username, password, login_util);

			return true;
		} catch(ExpiredTokenException | WrongChallengeAnswerException | DeniedAccessException e) {
			throw e;
		} catch(Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	// TODO: Colocar na interface?
	public boolean logout() {
		if(this.authToken!=null) {
			this.authToken = null;
			return true;
		} 

		return false;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(String username, String path) {

		return processRequest((location) -> {
			RestResponse response = client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addPathParam("ls")
					.addPathParam(username)
					.addPathParam(path)
					.get();

			if (response.getStatusCode() == 200) {
				System.out.println(new String( response.getHTTPReply().serialize()));
				return (List<String>) response.getEntity(List.class);
			} else
				throw new RuntimeException("ls: " + response.getStatusCode());
		});
	}

	public boolean mkdir(String username, String path) {

		return processRequest((location) -> {
			RestResponse response = client.newRequest(RemoteFileService.PATH).addHeader("Authorization", authToken.getBase64()).addPathParam("mkdir").addPathParam(username).addPathParam(path).post(null);

			if (response.getStatusCode() == 200) {
				return (boolean) response.getEntity(boolean.class);
			} else
				throw new RuntimeException("ls: " + response.getStatusCode());
		});
	}

	public boolean upload(String username, String path, byte[] data) {
		return processRequest((location) -> {
			RestResponse response = client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addPathParam("put")
					.addPathParam(username)
					.addPathParam(path)
					.put(data);

			if (response.getStatusCode() == 200) {
				return (boolean) response.getEntity(boolean.class);
			} else
				throw new RuntimeException("put: " + response.getStatusCode());
		});
	}


	public byte[] download(String username, String path) {
		return processRequest((location) -> {
			RestResponse response = client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addPathParam("get")
					.addPathParam(username)
					.addPathParam(path)
					.get();

			if (response.getStatusCode() == 200) {
				return (byte[]) response.getEntity(byte[].class);
			} else
				throw new RuntimeException("get: " + response.getStatusCode());
		});
	}


	public boolean copy(String username, String origin, String dest) {
		return processRequest((location) -> {
			
			RestResponse response= client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addPathParam("cp")
					.addPathParam(username)
					.addPathParam(origin)
					.addPathParam(dest)
					.put(null);
									
			if (response.getStatusCode() == 200) {
				return (boolean) response.getEntity(boolean.class);
			} else 
				throw new RuntimeException("cp: " + response.getStatusCode());
		});
	}

	public boolean remove(String username, String path) {
		return processRequest((location) -> {
			RestResponse response = client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addPathParam("rm")
					.addPathParam(username)
					.addPathParam(path)
					.delete(null);

			if (response.getStatusCode() == 200) {
				return (boolean) response.getEntity(boolean.class);
			} else
				throw new RuntimeException("rm: " + response.getStatusCode());
		});
	}

	public boolean removeDirectory(String username, String path) {
		return processRequest((location) -> {
			RestResponse response = client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addPathParam("rmdir")
					.addPathParam(username)
					.addPathParam(path)
					.delete(null);

			if (response.getStatusCode() == 200) {
				return (boolean) response.getEntity(boolean.class);
			} else
				throw new RuntimeException("rmDir: " + response.getStatusCode());
		});
	}

	public String getFileMetadata(String username, String path) {
		return processRequest((location) -> {
			RestResponse response = client.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", authToken.getBase64())
					.addPathParam("file")
					.addPathParam(username)
					.addPathParam(path)
					.get();

			if (response.getStatusCode() == 200) {
				return (String) response.getEntity(String.class);
			} else
				throw new RuntimeException("file: " + response.getStatusCode());
		});	
	}
	
	public AuthenticationToken getToken() {
		return authToken;
	}

}
