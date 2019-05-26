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

import fServer.storageServer.StorageService;
import fileService.RemoteFileService;
import rest.client.RestResponse;
import rest.client.mySecureRestClient;
import ssl.CustomSSLSocketFactory;
import utility.RequestHandler;

public class RemoteFileServiceClient implements RemoteFileService {

	private static final int MAX_TRIES = 3;
	private String location;
	private mySecureRestClient client;

	public RemoteFileServiceClient(KeyStore ks, String ks_password, KeyStore ts, String location)
			throws UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, UnknownHostException, CertificateException, IOException {
		this.location = location;
		this.client = new mySecureRestClient(new CustomSSLSocketFactory(ks, ks_password, ts), location);
	}

	// TODO: Vale a pena ter isto aqui?
	private <T> T processRequest(RequestHandler<T> requestHandler) {

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

	@Override
	public boolean login(String username, String password) {
		
		return processRequest((location) -> {
			RestResponse response = client.newRequest(RemoteFileService.PATH).addPathParam("login").addPathParam(username).post(password);

			if (response.getStatusCode() == 200) {
				return (boolean) response.getEntity(boolean.class);
			} else
				throw new RuntimeException("login: " + response.getStatusCode());
		});
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<String> listFiles(String username, String path) {
		
		return processRequest((location) -> {
			RestResponse response = client.newRequest(StorageService.PATH).addPathParam("ls").addPathParam(username).addPathParam(path).get();

			if (response.getStatusCode() == 200) {
				return (List<String>) response.getEntity(List.class);
			} else
				throw new RuntimeException("ls: " + response.getStatusCode());
		});
	}

	@Override
	public boolean mkdir(String username, String path) {
		
		return processRequest((location) -> {
			RestResponse response = client.newRequest(StorageService.PATH).addPathParam("mkdir").addPathParam(username).addPathParam(path).post(null);

			if (response.getStatusCode() == 200) {
				return (boolean) response.getEntity(boolean.class);
			} else
				throw new RuntimeException("ls: " + response.getStatusCode());
		});
	}

	@Override
	public boolean upload(String username, String path, byte[] data) {
		return processRequest((location) -> {
			RestResponse response = client.newRequest(StorageService.PATH).addPathParam("put").addPathParam(username).addPathParam(path).post(data);

			if (response.getStatusCode() == 200) {
				return (boolean) response.getEntity(boolean.class);
			} else
				throw new RuntimeException("put: " + response.getStatusCode());
		});
	}
	

	@Override
	public byte[] download(String username, String path) {
		return processRequest((location) -> {
			RestResponse response = client.newRequest(StorageService.PATH).addPathParam("get").addPathParam(username).addPathParam(path).get();

			if (response.getStatusCode() == 200) {
				return (byte[]) response.getEntity(byte[].class);
			} else
				throw new RuntimeException("get: " + response.getStatusCode());
		});
	}
	

	@Override
	public boolean copy(String username, String origin, String dest) {
		return processRequest((location) -> {
			RestResponse response = client.newRequest(StorageService.PATH).addPathParam("copy").addPathParam(username).addPathParam(origin).addPathParam(dest).post(null);

			if (response.getStatusCode() == 200) {
				return (boolean) response.getEntity(boolean.class);
			} else
				throw new RuntimeException("get: " + response.getStatusCode());
		});
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
	public boolean getFileMetadata(String username, String path) {
		// TODO Auto-generated method stub
		return false;
	}

}
