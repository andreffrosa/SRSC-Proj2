package client;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.List;

import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import fileService.RemoteFileService;
import utility.HTTPS;
import utility.RequestHandler;

public class RemoteFileServiceClient implements RemoteFileService {

	private static final int MAX_TRIES = 3;
	private String location;
	private Client client;

	public RemoteFileServiceClient(KeyStore ks, String ks_password, KeyStore ts, String tls_version, String ciphersuites,
			String location)
			throws UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
		this.location = location;
		this.client = HTTPS.buildClient(ks, ks_password, ts, tls_version, ciphersuites);
	}

	private <T> T processRequest(RequestHandler<T> requestHandler) {

		for (int current_try = 0; current_try < MAX_TRIES; current_try++) {
			try {
				return requestHandler.execute(location);
			} catch (ProcessingException e) {
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
			Response response = client.target(location).path(RemoteFileService.PATH + "/login/" + username).request()
					.post(Entity.entity(password, MediaType.APPLICATION_JSON));

			if (response.getStatus() == 200) {
				return (boolean) response.readEntity(boolean.class);
			} else
				throw new RuntimeException("login: " + response.getStatus());
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
