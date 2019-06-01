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

import javax.ws.rs.core.Response.Status;

import fServer.authServer.TokenVerifier;
import rest.RestResponse;

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
	public RestResponse listFiles(String token, String username, String path) {

		Path dirPath = buildPath(username, path);
		return new RestResponse("1.0", Status.OK.getStatusCode(), "Sending list", listFiles(dirPath)) ;
		
	}

	@Override
	public RestResponse mkdir(String token, String username, String path) {

		Path dirPath = buildPath(username, path);
		return new  RestResponse("1.0", Status.OK.getStatusCode(), "OK", new File(dirPath.toString()).mkdirs());
	}

	//TODO: Create metadata
	@Override
	public RestResponse upload(String token, String username, String path, byte[] data) {

		try {

			Path filePath = buildPath(username, path);
			Files.write(filePath, data);
			return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", true);

		} catch (IOException e) {
			return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", false);
		}
	}

	@Override
	public RestResponse download(String token, String username, String path) {

		try {
			Path filePath = buildPath(username, path);
			if(Files.exists(filePath) && Files.isReadable(filePath)) 
				return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", Files.readAllBytes(filePath));
		} catch (IOException e) { }

		return new RestResponse("1.0", Status.NOT_FOUND.getStatusCode(), "File not found", null);
	}

	@Override
	public RestResponse copy(String token, String username, String origin, String dest) {

		Path originPath = buildPath(username, origin);
		Path destPath = buildPath(username, dest);

		if(!Files.exists(originPath) || !Files.isReadable(originPath))
			return new RestResponse("1.0", 200, "OK", false);;

		try {

			Files.copy(originPath, destPath);
			return new RestResponse("1.0", 200, "OK", true);

		} catch (IOException e) {
			return new RestResponse("1.0", 200, "OK", false);
		}
	}

	@Override
	public RestResponse remove(String token, String username, String path) {

		Path filePath = buildPath(username, path);

		try {
			return new RestResponse("1.0", Status.OK.getStatusCode(), "OK",  Files.deleteIfExists(filePath));
		} catch (IOException e) {
			return new RestResponse("1.0", 200, "OK", false);
		}

	}

	@Override
	public RestResponse removeDirectory(String token, String username, String path) {
		
		Path dirPath = buildPath(username, path);
		if(listFiles(dirPath).size() > 0)
			return new RestResponse("1.0", 200, "OK", false);
		
		try {

			Files.delete(dirPath);
			return new RestResponse("1.0", 200, "OK", false);

		} catch (IOException e) {
			return new RestResponse("1.0", 200, "OK", false);
		}

	}

	@Override
	public RestResponse getFileMetadata(String token, String username, String path) {

		Path filePath = buildPath(username, path);
		try {
			if(Files.exists(filePath))
				return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", Files.readAttributes(filePath, BasicFileAttributes.class));

		}catch(IOException e){	}
		return new RestResponse("1.0", 200, "OK", null);
	}

	private Path buildPath(String username, String path) {

		//check if path is null
		if(path == null) path = "";

		//build path
		Path dirPath = Paths.get(username, path);
		return dirPath;
	}
	
	private List<String> listFiles(Path dirPath){
		
		if(Files.isDirectory(dirPath)) {			
			File dir = new File(dirPath.toString());
			return Arrays.asList(dir.list());
		}
		
		return new ArrayList<>(0);
	}
}