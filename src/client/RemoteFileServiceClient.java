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
			RestResponse response = client.newRequest(RemoteFileService.PATH).addPathParam(username).post(password);

			if (response.getStatusCode() == 200) {
				return (boolean) response.getEntity(boolean.class);
			} else
				throw new RuntimeException("login: " + response.getStatusCode());
		});
	}

	@Override
	public List<String> listFiles(String username, String path) {
		// TODO Auto-generated method stub
		return null;
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
	public boolean getFileMetadata(String username, String path) {
		// TODO Auto-generated method stub
		return false;
	}

}
