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

import fServer.accessControlServer.AcessControler;
import fServer.authServer.AuthenticationClient;
import fServer.authServer.AuthenticationToken;
import fServer.authServer.AuthenticatorService;
import fServer.authServer.DeniedAccessException;
import fServer.authServer.TokenVerifier;
import rest.RestResponse;
import rest.client.mySecureRestClient;
import ssl.CustomSSLSocketFactory;
import utility.RequestHandler;

public class MainDispatcherImplementation implements RemoteFileService, AuthenticatorService {

	private static final int MAX_TRIES = 3;

	private TokenVerifier tokenVerifier;
	private mySecureRestClient client;
	private String ac_server_location, storage_server_location;

	public MainDispatcherImplementation(String auth_server_location, String ac_server_location, String storage_server_location, TokenVerifier tokenVerifier, KeyStore ks, String ks_password, KeyStore ts) throws UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, UnknownHostException, CertificateException, IOException {
		SocketFactory factory = new CustomSSLSocketFactory(ks, ks_password, ts);
		client = new mySecureRestClient(factory, auth_server_location);
		this.ac_server_location = ac_server_location;
		this.storage_server_location = storage_server_location;
		this.tokenVerifier = tokenVerifier;
	}

	//Authentication methods
	@Override
	public RestResponse requestSession(String username)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, UnsupportedEncodingException, UnknownHostException, IOException, DeniedAccessException {

		return AuthenticationClient.get_requestSession(client, username, AuthenticatorService.PATH);
	}
	@Override
	public RestResponse requestToken(String username, String user_public_value, long client_nonce, byte[] credentials)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException,
			BadPaddingException, IOException, SignatureException, DeniedAccessException {

		return AuthenticationClient.post_requestToken(client, AuthenticatorService.PATH, username, user_public_value, client_nonce, credentials);
	}

	//HTTP processing helper functions
	private <K, T> T processRequest(String location, RequestHandler<String, T> requestHandler) {

		for (int current_try = 0; current_try < MAX_TRIES; current_try++) {
			try {
				return requestHandler.execute(location);
			} catch (Exception e) {
				System.out.println(String.format("Error contacting server %s .... retry: %d", location, current_try));
			}
		}

		throw new RuntimeException("Aborted request! Too many tries...");
	}

	private <K, T> RestResponse processRequest(String token, String opType ,RequestHandler<AuthenticationToken, RestResponse> requestHandler) throws Exception {

		AuthenticationToken auth = AuthenticationToken.parseToken(token);

		if(tokenVerifier.validateToken(System.currentTimeMillis(), auth)) {

			boolean hasAccess = processRequest(ac_server_location, (location) -> {
				RestResponse response = client.setLocation(ac_server_location)
						.newRequest(AcessControler.PATH)
						.addHeader("Authorization", auth.getBase64())
						.addPathParam(opType)
						.addPathParam(auth.getUsername())
						.get();

				if (response.getStatusCode() == 200) {
					System.out.println(new String( response.getHTTPReply().serialize()));
					return (boolean) response.getEntity(boolean.class);
				} else
					throw new RuntimeException("Acess Request: " + response.getStatusCode());
			});


			if(hasAccess)	
				return requestHandler.execute(auth);
			else
				return new RestResponse("1.0", 403, "Forbidden", String.format("%s has no permissions to %s\n.", auth.getUsername(), opType));
		} else {
			return new RestResponse("1.0", 403, "Forbidden", "token is expired!".getBytes());
		}
	}

	//main functionalities implementation
	@Override
	public RestResponse listFiles(String token, String username, String path) throws Exception {

		return processRequest(token, AcessControler.READ_ACCESS_REQUEST , (auth) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", auth.getBase64())
					.addPathParam("ls")
					.addPathParam(username)
					.addPathParam(path)
					.get();
		});
	}

	@Override
	public RestResponse mkdir(String token, String username, String path) throws Exception {
		return processRequest(token, AcessControler.WRITE_ACCESS_REQUEST , (auth) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", auth.getBase64())
					.addPathParam("mkdir")
					.addPathParam(username)
					.addPathParam(path)
					.post(null);
		});	
	}

	@Override
	public RestResponse upload(String token, String username, String path, byte[] data) throws Exception {
		return processRequest(token, AcessControler.WRITE_ACCESS_REQUEST ,(auth) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", auth.getBase64())
					.addPathParam("put")
					.addPathParam(username)
					.addPathParam(path)
					.post(data);
		});	
	}

	@Override
	public RestResponse download(String token, String username, String path) throws Exception {
		return processRequest(token, AcessControler.READ_ACCESS_REQUEST ,(auth) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", auth.getBase64())
					.addPathParam("get")
					.addPathParam(username)
					.addPathParam(path)
					.get();
		});	
	}

	@Override
	public RestResponse copy(String token, String username, String origin, String dest) throws Exception {
		return processRequest(token, AcessControler.WRITE_ACCESS_REQUEST ,(auth) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", auth.getBase64())
					.addPathParam("copy")
					.addPathParam(username)
					.addPathParam(origin)
					.addPathParam(dest)
					.post(null);
		});	
	}

	@Override
	public RestResponse remove(String token, String username, String path) throws Exception {
		return processRequest(token, AcessControler.READ_ACCESS_REQUEST ,(auth) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", auth.getBase64())
					.addPathParam("rm")
					.addPathParam(username)
					.addPathParam(path)
					.delete(null);
		});	
	}

	@Override
	public RestResponse removeDirectory(String token, String username, String path) throws Exception {
		return processRequest(token, AcessControler.READ_ACCESS_REQUEST ,(auth) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", auth.getBase64())
					.addPathParam("rmdir")
					.addPathParam(username)
					.addPathParam(path)
					.delete(null);
		});	
	}

	@Override
	public RestResponse getFileMetadata(String token, String username, String path) throws Exception {
		return processRequest(token, AcessControler.READ_ACCESS_REQUEST ,(auth) -> {
			return	client.setLocation(storage_server_location)
					.newRequest(RemoteFileService.PATH)
					.addHeader("Authorization", auth.getBase64())
					.addPathParam("file")
					.addPathParam(username)
					.addPathParam(path)
					.get();
		});	
	}

}
