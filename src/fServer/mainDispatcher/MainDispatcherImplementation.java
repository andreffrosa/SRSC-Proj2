package fServer.mainDispatcher;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.UnknownHostException;
import java.nio.file.attribute.BasicFileAttributes;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.net.SocketFactory;

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

	private TokenVerifier tokenVerifier;
	private mySecureRestClient authClient;

	public MainDispatcherImplementation(String auth_server_location, String ac_server_location, String storage_server_location, TokenVerifier tokenVerifier, KeyStore ks, String ks_password, KeyStore ts) throws UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, UnknownHostException, CertificateException, IOException {
		SocketFactory factory = new CustomSSLSocketFactory(ks, ks_password, ts);
		this.authClient = new mySecureRestClient(factory, auth_server_location);
		this.tokenVerifier = tokenVerifier;
	}

	@Override
	public RestResponse requestSession(String username)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, UnsupportedEncodingException, UnknownHostException, IOException, DeniedAccessException {

		return AuthenticationClient.get_requestSession(authClient, AuthenticatorService.PATH, username);
	}

	@Override
	public RestResponse requestToken(String username, long client_nonce, byte[] credentials)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException,
			BadPaddingException, IOException, SignatureException, DeniedAccessException {

		return AuthenticationClient.post_requestToken(authClient, AuthenticatorService.PATH, username, client_nonce, credentials);
	}

	private <K, T> RestResponse processRequest(String token, RequestHandler<AuthenticationToken, RestResponse> requestHandler) throws Exception {

		AuthenticationToken auth = AuthenticationToken.parseToken(token);

		if(tokenVerifier.validateToken(System.currentTimeMillis(), auth)) {

			return requestHandler.execute(auth);
		} else {
			return new RestResponse("1.0", 403, "Forbidden", "token is expired!".getBytes());
		}
	}

	// TODO: remover o username porque o token já o tem
	@Override
	public RestResponse listFiles(String token, String username, String path) throws Exception {
		
		return processRequest(token, (auth) -> {
			List<String> list = new ArrayList<String>(1);
			
			// TODO:

			return new RestResponse("1.0", 200, "OK", list);
		} );

	}

	@Override
	public boolean mkdir(String username, String path) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean upload(String username, String path, byte[] data) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public byte[] download(String username, String path) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean copy(String username, String origin, String dest) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean remove(String username, String path) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean removeDirectory(String username, String path) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public BasicFileAttributes getFileMetadata(String username, String path) {
		// TODO Auto-generated method stub
		return null;
	}

}
