package fServer.storageServer.dropbox;

import java.security.MessageDigest;

import fServer.storageServer.StorageAbstract;
import rest.RestResponse;
import token.TokenVerifier;

public abstract class CloudStorage extends StorageAbstract  {
	
	private String cloudProvider;

	public CloudStorage(String cloudProvider, TokenVerifier authTokenVerifier, TokenVerifier accessTokenVerifier,
			MessageDigest hash_function) {
		super(authTokenVerifier, accessTokenVerifier, hash_function);
		this.cloudProvider = cloudProvider;
	}

	@Override
	public abstract RestResponse listFiles(String token, String access_token, long nonce, String username, String path) throws Exception ;
	
	@Override
	public abstract RestResponse mkdir(String token, String access_token, long nonce, String username, String path) throws Exception ;

	@Override
	public abstract RestResponse upload(String token, String access_token, long nonce, String username, String path, byte[] data) throws Exception;

	@Override
	public abstract RestResponse download(String token, String access_token, long nonce, String username, String path) throws Exception;

	@Override
	public abstract RestResponse copy(String token, String access_token, long nonce, String username, String src, String dest) throws Exception;

	@Override
	public abstract RestResponse remove(String token, String access_token, long nonce, String username, String path) throws Exception;

	@Override
	public abstract RestResponse removeDirectory(String token, String access_token, long nonce, String username, String path) throws Exception;

	@Override
	public abstract RestResponse getFileMetadata(String token, String access_token, long nonce, String username, String path) throws Exception;
	
	public String getCloudProvider() {
		return cloudProvider;
	}
}
