package fServer.mainDispatcher;

import java.util.List;

import fileService.RemoteFileService;

public class MainDispatcherImplementation implements RemoteFileService {

	@Override
	public boolean login(String username, String password) {
		// TODO Auto-generated method stub
		System.out.println(username + ": " + password);
		return false;
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
