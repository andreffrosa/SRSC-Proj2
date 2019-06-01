/**
 * 
 */
package fServer.storageServer;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import fServer.authServer.TokenVerifier;

/**
 * @author ruben
 *
 *This class is an implementation of the Storage Service.
 *
 */
public class StorageImplementation implements StorageService {

	private TokenVerifier tokenVerifier;
	
	//TODO: all syncronized
	//TODO: O que significa tabelas no enunciado	
	public StorageImplementation(TokenVerifier tokenVerifier) {
		this.tokenVerifier = tokenVerifier;
	}

	@Override
	public List<String> listFiles(String username, String path) {

		Path dirPath = buildPath(username, path);

		if(Files.isDirectory(dirPath)) {			
			File dir = new File(dirPath.toString());
			return Arrays.asList(dir.list());
		}

		return new ArrayList<>(0);
	}

	@Override
	public boolean mkdir(String username, String path) {

		Path dirPath = buildPath(username, path);
		return new File(dirPath.toString()).mkdirs();
	}

	//TODO: Create metadata
	@Override
	public boolean upload(String username, String path, byte[] data) {

		try {

			Path filePath = buildPath(username, path);
			Files.write(filePath, data);
			return true;

		} catch (IOException e) {
			return false;
		}
	}

	@Override
	public byte[] download(String username, String path) {

		try {
			Path filePath = buildPath(username, path);
			if(Files.exists(filePath) && Files.isReadable(filePath)) 
				return Files.readAllBytes(filePath);
		} catch (IOException e) { }

		return null; //TODO: better return or in server check is null to send not found code.
	}

	@Override
	public boolean copy(String username, String origin, String dest) {

		Path originPath = buildPath(username, origin);
		Path destPath = buildPath(username, dest);

		if(!Files.exists(originPath) || !Files.isReadable(originPath))
			return false;

		try {

			Files.copy(originPath, destPath.resolve(originPath.getFileName()));
			return true;

		} catch (IOException e) {
			return false;
		}
	}

	@Override
	public boolean remove(String username, String path) {

		Path filePath = buildPath(username, path);

		try {
			return Files.deleteIfExists(filePath);
		} catch (IOException e) {
			return false;
		}

	}

	@Override
	public boolean removeDirectory(String username, String path) {

		if(listFiles(username, path).size() > 0)
			return false;

		Path dirPath = buildPath(username, path);
		try {

			Files.delete(dirPath);
			return true;

		} catch (IOException e) {
			return false;
		}



	}

	@Override
	public BasicFileAttributes getFileMetadata(String username, String path) {

		Path filePath = buildPath(username, path);
		try {
			if(Files.exists(filePath))
				return Files.readAttributes(filePath, BasicFileAttributes.class);

		}catch(IOException e){	}
		return null;
	}

	private Path buildPath(String username, String path) {

		//check if path is null
		if(path == null) path = "";

		//build path
		Path dirPath = Paths.get(username, path);
		return dirPath;
	}

}
