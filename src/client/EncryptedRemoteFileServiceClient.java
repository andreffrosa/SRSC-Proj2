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
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.ws.rs.core.Response.Status;

import client.exception.FileNotFoundException;
import client.exception.LogginRequieredException;
import client.exception.UnautorizedException;
import client.proxy.EncryptedFileSystem;
import client.proxy.inodes.DataFragment;
import client.proxy.inodes.FileDescriptor;
import client.proxy.inodes.FileDescriptor.FragmentMetaData;
import fServer.authServer.AuthenticationClient;
import fServer.authServer.exceptions.DeniedAccessException;
import fServer.authServer.exceptions.WrongChallengeAnswerException;
import fServer.mainDispatcher.RemoteFileService;
import rest.RestResponse;
import rest.client.mySecureRestClient;
import ssl.CustomSSLSocketFactory;
import token.ExpiredTokenException;
import token.auth.AuthenticationToken;
import utility.Cryptography;
import utility.LoginUtility;
import utility.RequestHandler;

public class EncryptedRemoteFileServiceClient{

	private static final int MAX_TRIES = 3;
	private String location;
	private mySecureRestClient client;
	private AuthenticationToken authToken;
	private LoginUtility login_util; 
	private EncryptedFileSystem fs;

	public EncryptedRemoteFileServiceClient(String fs_configs, KeyStore ks, String ks_password, KeyStore ts, String location, LoginUtility login_util)
			throws UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, UnknownHostException, CertificateException, IOException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		this.location = location;
		this.client = new mySecureRestClient(new CustomSSLSocketFactory(ks, ks_password, ts), location);
		this.authToken = null;
		this.login_util = login_util;
		this.fs = EncryptedFileSystem.load(fs_configs);
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

	public List<String> listFiles(String username, String path)  throws LogginRequieredException, UnautorizedException, FileNotFoundException {
		return fs.listFiles(path);
	}

	public boolean mkdir(String username, String path) throws LogginRequieredException, UnautorizedException {
		fs.store();
		return fs.mkdir(path);
	}

	public boolean upload(String username, String path, byte[] data) throws LogginRequieredException, UnautorizedException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, SignatureException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, IOException, FileNotFoundException {
		
		DataFragment[] fragments = fs.write(path, data);
		fs.store();
		
		for(DataFragment f : fragments) {
			String nonce = "" + Cryptography.genNonce(login_util.getRandom());
			RestResponse response = processRequest((location) -> {
				return client.newRequest(RemoteFileService.PATH)
						.addHeader("Authorization", authToken.getBase64())
						.addHeader("Access", null)
						.addHeader("nonce", nonce)
						.addPathParam("put")
						.addPathParam(username)
						.addPathParam(f.getName())
						.put(f.serialize());
			});
			
			// TODO: O que fazer quando dá erro? Ir ao fs e apagar?
			if(response.getStatusCode() == Status.UNAUTHORIZED.getStatusCode()) {
				fs.remove(path);
				throw new LogginRequieredException("Invalid Loggin.\n");
			}else if(response.getStatusCode() == Status.FORBIDDEN.getStatusCode() ) {
				fs.remove(path);
				throw new UnautorizedException("Access denied.\n");			
			} else {
				fs.remove(path);
				throw new RuntimeException("put: " + response.getStatusCode());
			}
		}
		
		return true;
	}

	public byte[] download(String username, String path) throws LogginRequieredException, UnautorizedException, FileNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IOException {
		
		FileDescriptor fd = fs.getFileDescriptor(path);
		FragmentMetaData[] meta = fd.getFragmentsMetaData();
		
		byte[][] raw_fragments = new byte[meta.length][];
		
		for(int i = 0; i < raw_fragments.length; i++) {
			String name = meta[i].name;
			String nonce = "" + Cryptography.genNonce(login_util.getRandom());
			RestResponse response = processRequest((location) -> {
				return client.newRequest(RemoteFileService.PATH)
						.addHeader("Authorization", authToken.getBase64())
						.addHeader("Access", null)
						.addHeader("nonce", nonce)
						.addPathParam("get")
						.addPathParam(username)
						.addPathParam(name)
						.get();
			});
		
			if (response.getStatusCode() == Status.OK.getStatusCode()) {
				raw_fragments[i] = (byte[]) response.getEntity(byte[].class);
			}else if(response.getStatusCode() == Status.UNAUTHORIZED.getStatusCode()) {
				throw new LogginRequieredException("Invalid Loggin.\n");
			}else if(response.getStatusCode() == Status.FORBIDDEN.getStatusCode() ) {
				throw new UnautorizedException("Access denied.\n");
			}else if(response.getStatusCode() == Status.NOT_FOUND.getStatusCode()) {
				throw new FileNotFoundException("File Not Found.\n");
			} else
				throw new RuntimeException("get: " + response.getStatusCode());
		}
		
		return fs.assemble(fd, raw_fragments);
	}

	public boolean copy(String username, String origin, String dest) throws LogginRequieredException, UnautorizedException, FileNotFoundException {
		
		Map<String, String> map = fs.copy(origin, dest);
		fs.store();
		
		for(Entry<String, String> e : map.entrySet()) {
			String nonce = "" + Cryptography.genNonce(login_util.getRandom());
			RestResponse response = processRequest((location) -> {
				return client.newRequest(RemoteFileService.PATH)
						.addHeader("Authorization", authToken.getBase64())
						.addHeader("Access", null)
						.addHeader("nonce", nonce)
						.addPathParam("cp")
						.addPathParam(username)
						.addPathParam(e.getKey())
						.addPathParam(e.getValue())
						.put(null);
			});
		
			if(response.getStatusCode() == Status.UNAUTHORIZED.getStatusCode()) {
				fs.remove(dest);
				throw new LogginRequieredException("Invalid Loggin.\n");
			}else if(response.getStatusCode() == Status.FORBIDDEN.getStatusCode() ) {
				fs.remove(dest);
				throw new UnautorizedException("Access denied.\n");
			}else if(response.getStatusCode() == Status.NOT_FOUND.getStatusCode()) {
				fs.remove(dest);
				throw new FileNotFoundException("File Not Found.\n");
			} else {
				fs.remove(dest);
				throw new RuntimeException("cp: " + response.getStatusCode());
			}
		}
		
		return true;
	}
	
	public boolean remove(String username, String path) throws LogginRequieredException, UnautorizedException, FileNotFoundException {
		
		List<String> fragments = fs.remove(path);
		fs.store();
		
		for(String frag : fragments) {
			String nonce = "" + Cryptography.genNonce(login_util.getRandom());
			RestResponse response = processRequest((location) -> {
				return client.newRequest(RemoteFileService.PATH)
						.addHeader("Authorization", authToken.getBase64())
						.addHeader("Access", null)
						.addHeader("nonce", nonce)
						.addPathParam("rm")
						.addPathParam(username)
						.addPathParam(frag)
						.delete(null);
			});
			
			if(response.getStatusCode() == Status.UNAUTHORIZED.getStatusCode()) {
				throw new LogginRequieredException("Invalid Loggin.\n");
			}else if(response.getStatusCode() == Status.FORBIDDEN.getStatusCode() ) {
				throw new UnautorizedException("Access denied.\n");
			}else if(response.getStatusCode() == Status.NOT_FOUND.getStatusCode()) {
				throw new FileNotFoundException("File not found.");
			} else
				throw new RuntimeException("rm: " + response.getStatusCode());
		}
		return true;
	}

	public boolean removeDirectory(String username, String path) throws LogginRequieredException, UnautorizedException, FileNotFoundException {
		fs.store();
		return fs.removeDirectory(path);
	}

	public String getFileMetadata(String username, String path) throws LogginRequieredException, UnautorizedException, FileNotFoundException {
		return fs.getFileMetadata(path);
	}

	public AuthenticationToken getToken() {
		return authToken;
	}
}
