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
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.ws.rs.core.Response.Status;

import fServer.authServer.AuthenticationToken;
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
	private String dbPath;
	
	//TODO: all syncronized
	//TODO: O que significa tabelas no enunciado	
	public StorageImplementation(String dbPath, TokenVerifier tokenVerifier) {
		this.tokenVerifier = tokenVerifier;
		this.dbPath = dbPath;
	}

	@Override
	public RestResponse listFiles(String token, String username, String path) throws IOException, InvalidKeyException, SignatureException {
		
		AuthenticationToken auth = AuthenticationToken.parseToken(token);
		if(!tokenVerifier.validateToken(System.currentTimeMillis(), auth)) {
			System.out.println("User " + username + " presented invalid token");
			return new RestResponse("1.0", Status.FORBIDDEN.getStatusCode(), "Forbidden", "Invalid Token.");
		}
		
		Path dirPath = buildPath(username, path);
		return new RestResponse("1.0", Status.OK.getStatusCode(), "Sending list", listFiles(dirPath)) ;
		
	}

	@Override
	public RestResponse mkdir(String token, String username, String path) throws InvalidKeyException, SignatureException, IOException {
		
		AuthenticationToken auth = AuthenticationToken.parseToken(token);
		if(!tokenVerifier.validateToken(System.currentTimeMillis(), auth)) {
			System.out.println("User " + username + " presented invalid token");
			return new RestResponse("1.0", Status.FORBIDDEN.getStatusCode(), "Forbidden", "Invalid Token.");
		}
		
		Path dirPath = buildPath(username, path);
		return new  RestResponse("1.0", Status.OK.getStatusCode(), "OK", new File(dirPath.toString()).mkdirs());
	}

	@Override
	public RestResponse upload(String token, String username, String path, byte[] data) throws IOException, InvalidKeyException, SignatureException {
		
		AuthenticationToken auth = AuthenticationToken.parseToken(token);
		if(!tokenVerifier.validateToken(System.currentTimeMillis(), auth)) {
			System.out.println("User " + username + " presented invalid token");
			return new RestResponse("1.0", Status.FORBIDDEN.getStatusCode(), "Forbidden", "Invalid Token.");
		}
		
		try {

			Path filePath = buildPath(username, path);
			Files.write(filePath, data);
			return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", true);

		} catch (IOException e) {
			return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", false);
		}
	}

	@Override
	public RestResponse download(String token, String username, String path) throws IOException, InvalidKeyException, SignatureException {
		
		AuthenticationToken auth = AuthenticationToken.parseToken(token);
		if(!tokenVerifier.validateToken(System.currentTimeMillis(), auth)) {
			System.out.println("User " + username + " presented invalid token");
			return new RestResponse("1.0", Status.FORBIDDEN.getStatusCode(), "Forbidden", "Invalid Token.");
		}
		
		try {
			Path filePath = buildPath(username, path);
			if(Files.exists(filePath) && Files.isReadable(filePath)) 
				return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", Files.readAllBytes(filePath));
		} catch (IOException e) { }

		return new RestResponse("1.0", Status.NOT_FOUND.getStatusCode(), "File not found", null);
	}

	@Override
	public RestResponse copy(String token, String username, String origin, String dest) throws InvalidKeyException, SignatureException, IOException {
		
		AuthenticationToken auth = AuthenticationToken.parseToken(token);
		if(!tokenVerifier.validateToken(System.currentTimeMillis(), auth)) {
			System.out.println("User " + username + " presented invalid token");
			return new RestResponse("1.0", Status.FORBIDDEN.getStatusCode(), "Forbidden", "Invalid Token.");
		}
		
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
	public RestResponse remove(String token, String username, String path) throws IOException, InvalidKeyException, SignatureException {
		
		AuthenticationToken auth = AuthenticationToken.parseToken(token);
		if(!tokenVerifier.validateToken(System.currentTimeMillis(), auth)) {
			System.out.println("User " + username + " presented invalid token");
			return new RestResponse("1.0", Status.FORBIDDEN.getStatusCode(), "Forbidden", "Invalid Token.");
		}
		
		Path filePath = buildPath(username, path);

		try {
			return new RestResponse("1.0", Status.OK.getStatusCode(), "OK",  Files.deleteIfExists(filePath));
		} catch (IOException e) {
			return new RestResponse("1.0", 200, "OK", false);
		}

	}

	@Override
	public RestResponse removeDirectory(String token, String username, String path) throws InvalidKeyException, SignatureException, IOException {
		
		AuthenticationToken auth = AuthenticationToken.parseToken(token);
		if(!tokenVerifier.validateToken(System.currentTimeMillis(), auth)) {
			System.out.println("User " + username + " presented invalid token");
			return new RestResponse("1.0", Status.FORBIDDEN.getStatusCode(), "Forbidden", "Invalid Token.");
		}
		
		Path dirPath = buildPath(username, path);
		if(listFiles(dirPath).size() > 0)
			return new RestResponse("1.0", 200, "OK", false);
		
		try {

			Files.delete(dirPath);
			return new RestResponse("1.0", 200, "OK", true);

		} catch (IOException e) {
			return new RestResponse("1.0", 200, "OK", false);
		}

	}

	@Override
	public RestResponse getFileMetadata(String token, String username, String path) throws IOException, InvalidKeyException, SignatureException {
		
		AuthenticationToken auth = AuthenticationToken.parseToken(token);
		if(!tokenVerifier.validateToken(System.currentTimeMillis(), auth)) {
			System.out.println("User " + username + " presented invalid token");
			return new RestResponse("1.0", Status.FORBIDDEN.getStatusCode(), "Forbidden", "Invalid Token.");
		}
		
		Path filePath = buildPath(username, path);
		try {
			if(Files.exists(filePath)) {
				int idx = path.lastIndexOf(".");
				String ext =  idx > 0 ? path.substring(idx) : "-";
				BasicFileAttributes bfa =  Files.readAttributes(filePath, BasicFileAttributes.class);
				String metadata = String.format("%s\t%s\t%s\tCreated on: %s\tLast Access on: %s\n", path, bfa.isDirectory() ? "D" : "F", ext , new Date(bfa.creationTime().toMillis()), new Date( bfa.lastModifiedTime().toMillis()));
				return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", metadata);
			}
		}catch(IOException e){	}
		return new RestResponse("1.0", Status.NOT_FOUND.getStatusCode(), "NOT FOUND", null);
	}

	private Path buildPath(String username, String path) {

		//check if path is null
		if(path == null) path = "";

		//build path
		Path dirPath = Paths.get(dbPath, username, path);
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