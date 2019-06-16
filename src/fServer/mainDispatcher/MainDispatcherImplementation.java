package fServer.mainDispatcher;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.net.SocketFactory;
import javax.ws.rs.core.Response.Status;

import fServer.accessControlServer.AccessControler;
import fServer.authServer.AuthenticationClient;
import fServer.authServer.AuthenticatorService;
import fServer.authServer.DeniedAccessException;
import fServer.storageServer.StorageService;
import rest.RestResponse;
import rest.client.mySecureRestClient;
import ssl.CustomSSLSocketFactory;
import token.Token;
import token.TokenVerifier;
import token.access.AccessToken;
import token.auth.AuthenticationToken;
import utility.RequestHandler;

public class MainDispatcherImplementation implements RemoteFileService, AuthenticatorService, StorageService {

	
	private static final int MAX_TRIES = 3;

	private TokenVerifier authTokenVerifier;
	private TokenVerifier accessTokenVerifier;
	private mySecureRestClient client;
	private String ac_server_location, storage_server_location;

	public MainDispatcherImplementation(String auth_server_location, String ac_server_location, String storage_server_location, TokenVerifier authTokenVerifier, TokenVerifier accessTokenVerifier, KeyStore ks, String ks_password, KeyStore ts) throws UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, UnknownHostException, CertificateException, IOException {
		SocketFactory factory = new CustomSSLSocketFactory(ks, ks_password, ts);
		client = new mySecureRestClient(factory, auth_server_location);
		this.ac_server_location = ac_server_location;
		this.storage_server_location = storage_server_location;
		this.authTokenVerifier = authTokenVerifier;
		this.accessTokenVerifier = accessTokenVerifier;
	}

	//Authentication methods
	@Override
	public synchronized RestResponse requestSession(String username)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, UnsupportedEncodingException, UnknownHostException, IOException, DeniedAccessException {

		return AuthenticationClient.get_requestSession(client, AuthenticatorService.PATH, username);
	}
	
	@Override
	public synchronized RestResponse requestToken(String username, long client_nonce, byte[] credentials)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException,
			BadPaddingException, IOException, SignatureException, DeniedAccessException {

		return AuthenticationClient.post_requestToken(client, AuthenticatorService.PATH, username, client_nonce, credentials);
	}

	//HTTP processing helper functions
	private synchronized <K, T> T processRequest(String location, RequestHandler<String, T> requestHandler) {

		for (int current_try = 0; current_try < MAX_TRIES; current_try++) {
			try {
				return requestHandler.execute(location);
			} catch (Exception e) {
				System.out.println(String.format("Error contacting server %s .... retry: %d", location, current_try));
			}
		}

		throw new RuntimeException("Aborted request! Too many tries...");
	}

	private synchronized <K,T> RestResponse processRequest(String auth_token, String opType, String params, long nonce, RequestHandler<Token[], RestResponse> requestHandler) throws Exception {
		
		AuthenticationToken auth = AuthenticationToken.parseToken(auth_token, null);
		if(authTokenVerifier.validateToken(System.currentTimeMillis(), auth)) {

			RestResponse response = processRequest(ac_server_location, (location) -> {
				return client.setLocation(ac_server_location)
						.newRequest(AccessControler.PATH)
						.addHeader("Authorization", auth.getBase64())
						.addPathParam(auth.getUsername())
						.addPathParam(opType)
						.addPathParam(params)
						.addPathParam(""+nonce)
						.get();
			});
			
			if (response.getStatusCode() == Status.OK.getStatusCode()) {
				AccessToken access_token = AccessToken.parseToken(response.getEntity(String.class));
				
				if(accessTokenVerifier.validateToken(System.currentTimeMillis(), access_token)) {
					return requestHandler.execute(new Token[] {auth, access_token});
				} else {
					return new RestResponse("1.0", 403, "Forbidden", "Access token is invalid!".getBytes());
				}
			} else
				return response;
		} else {
			return new RestResponse("1.0", 403, "Forbidden", "Authentication token is invalid!".getBytes());
		}
	}

	//main functionalities implementation
	@Override
	public synchronized RestResponse listFiles(String auth_token, String access_token, long nonce, String username, String path) throws Exception {
		return processRequest(auth_token, AccessControler.READ_ACCESS_REQUEST, username+path, nonce, (tokens) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(StorageService.PATH)
					.addHeader("Authorization", tokens[0].getBase64())
					.addHeader("Access", tokens[1].getBase64())
					.addHeader("nonce", ""+nonce)
					.addPathParam("ls")
					.addPathParam(username)
					.addPathParam(path)
					.get();
		});
	}

	@Override
	public synchronized RestResponse mkdir(String auth_token, String access_token, long nonce, String username, String path) throws Exception {
		return processRequest(auth_token, AccessControler.WRITE_ACCESS_REQUEST, username+path, nonce, (tokens) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(StorageService.PATH)
					.addHeader("Authorization", tokens[0].getBase64())
					.addHeader("Access", tokens[1].getBase64())
					.addPathParam("mkdir")
					.addPathParam(username)
					.addPathParam(path)
					.post(null);
		});	
	}

	@Override
	public synchronized RestResponse upload(String auth_token, String access_token, long nonce, String username, String path, byte[] data) throws Exception {
		return processRequest(auth_token, AccessControler.WRITE_ACCESS_REQUEST, username+path+java.util.Base64.getEncoder().encodeToString(data), nonce, (tokens) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(StorageService.PATH)
					.addHeader("Authorization", tokens[0].getBase64())
					.addHeader("Access", tokens[1].getBase64())
					.addPathParam("put")
					.addPathParam(username)
					.addPathParam(path)
					.put(data);
		});	
	}

	@Override
	public synchronized RestResponse download(String auth_token, String access_token, long nonce, String username, String path) throws Exception {
		return processRequest(auth_token, AccessControler.READ_ACCESS_REQUEST, username+path, nonce, (tokens) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(StorageService.PATH)
					.addHeader("Authorization", tokens[0].getBase64())
					.addHeader("Access", tokens[1].getBase64())
					.addPathParam("get")
					.addPathParam(username)
					.addPathParam(path)
					.get();
		});	
	}

	@Override
	public synchronized RestResponse copy(String auth_token, String access_token, long nonce, String username, String origin, String dest) throws Exception {
		return processRequest(auth_token, AccessControler.WRITE_ACCESS_REQUEST, username+origin+dest, nonce, (tokens) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(StorageService.PATH)
					.addHeader("Authorization", tokens[0].getBase64())
					.addHeader("Access", tokens[1].getBase64())
					.addPathParam("cp")
					.addPathParam(username)
					.addPathParam(origin)
					.addPathParam(dest)
					.put(null);
		});	
	}

	@Override
	public synchronized RestResponse remove(String auth_token, String access_token, long nonce, String username, String path) throws Exception {
		return processRequest(auth_token, AccessControler.WRITE_ACCESS_REQUEST, username+path, nonce, (tokens) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(StorageService.PATH)
					.addHeader("Authorization", tokens[0].getBase64())
					.addHeader("Access", tokens[1].getBase64())
					.addPathParam("rm")
					.addPathParam(username)
					.addPathParam(path)
					.delete(null);
		});	
	}

	@Override
	public synchronized RestResponse removeDirectory(String auth_token, String access_token, long nonce, String username, String path) throws Exception {
		return processRequest(auth_token, AccessControler.WRITE_ACCESS_REQUEST, username+path, nonce, (tokens) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(StorageService.PATH)
					.addHeader("Authorization", tokens[0].getBase64())
					.addHeader("Access", tokens[1].getBase64())
					.addPathParam("rmdir")
					.addPathParam(username)
					.addPathParam(path)
					.delete(null);
		});	
	}

	@Override
	public synchronized RestResponse getFileMetadata(String auth_token, String access_token, long nonce, String username, String path) throws Exception {
		return processRequest(auth_token, AccessControler.READ_ACCESS_REQUEST, username+path, nonce, (tokens) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(StorageService.PATH)
					.addHeader("Authorization", tokens[0].getBase64())
					.addHeader("Access", tokens[1].getBase64())
					.addPathParam("file")
					.addPathParam(username)
					.addPathParam(path)
					.get();
		});	
	}

}
