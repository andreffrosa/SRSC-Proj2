package fServer.storageServer;

import java.security.MessageDigest;

import rest.RestResponse;
import token.TokenVerifier;
import token.access.AccessToken;
import token.auth.AuthenticationToken;
import utility.Cryptography;
import utility.RequestHandler;

public abstract class StorageAbstract implements StorageService {
	
	private TokenVerifier authTokenVerifier;
	private TokenVerifier accessTokenVerifier;
	private MessageDigest hash_function;
	
	public StorageAbstract(TokenVerifier authTokenVerifier, TokenVerifier accessTokenVerifier, MessageDigest hash_function) {
		this.authTokenVerifier = authTokenVerifier;
		this.accessTokenVerifier = accessTokenVerifier;
		this.hash_function = hash_function;
	}
	
	protected synchronized boolean verifyIntegrity(byte[] rcv_hash, String op_params, String op_type, long nonce) {
		String data = op_params + op_type + nonce;
		byte[] computed_hash = Cryptography.digest(hash_function, data.getBytes());

		return MessageDigest.isEqual(rcv_hash, computed_hash);
	}

	protected synchronized <K,T> RestResponse processRequest(String auth_token, String access_token, String op_params, String op_type, long nonce, RequestHandler<AuthenticationToken, RestResponse> requestHandler) throws Exception {
		AuthenticationToken auth = AuthenticationToken.parseToken(auth_token, null);
		if(authTokenVerifier.validateToken(System.currentTimeMillis(), auth)) {

			AccessToken ac_token = AccessToken.parseToken(access_token);
			if(accessTokenVerifier.validateToken(System.currentTimeMillis(), ac_token)) {
				if(verifyIntegrity(ac_token.getHash(), op_params, op_type, nonce))
					return requestHandler.execute(auth);
				else
					return new RestResponse("1.0", 403, "Forbidden", "Invalid Access Token: hash is different!".getBytes());
			} else {
				return new RestResponse("1.0", 403, "Forbidden", "Invalid Access Token!".getBytes());
			}
		} else {
			return new RestResponse("1.0", 403, "Forbidden", "Invalid Authentication Token!".getBytes());
		}
	}
	
	
	@Override
	public abstract RestResponse listFiles(String token, String access_token, long nonce, String username, String path)	throws Exception;

	@Override
	public abstract RestResponse mkdir(String token, String access_token, long nonce, String username, String path)	throws Exception;

	@Override
	public abstract RestResponse upload(String token, String access_token, long nonce, String username, String path, byte[] data) throws Exception ;

	@Override
	public abstract RestResponse download(String token, String access_token, long nonce, String username, String path) throws Exception ;

	@Override
	public abstract RestResponse copy(String token, String access_token, long nonce, String username, String src, String dest) throws Exception;

	@Override
	public abstract RestResponse remove(String token, String access_token, long nonce, String username, String path) throws Exception;

	@Override
	public abstract RestResponse removeDirectory(String token, String access_token, long nonce, String username, String path) throws Exception;

	@Override
	public abstract RestResponse getFileMetadata(String token, String access_token, long nonce, String username, String path) throws Exception;

}
