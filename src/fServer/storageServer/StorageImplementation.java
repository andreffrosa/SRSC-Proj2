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
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.ws.rs.core.Response.Status;

import fServer.accessControlServer.AccessControler;
import rest.RestResponse;
import token.TokenVerifier;
import token.access.AccessToken;
import token.auth.AuthenticationToken;
import utility.Cryptography;
import utility.RequestHandler;

/**
 * @author Ruben & Andre
 *
 *This class is an implementation of the Storage Service.
 *
 */
public class StorageImplementation implements StorageService {

	private TokenVerifier authTokenVerifier;
	private TokenVerifier accessTokenVerifier;
	private MessageDigest hash_function;
	private String dbPath;

	public StorageImplementation(String dbPath, TokenVerifier authTokenVerifier, TokenVerifier accessTokenVerifier, MessageDigest hash_function) {
		this.authTokenVerifier = authTokenVerifier;
		this.accessTokenVerifier = accessTokenVerifier;
		this.hash_function = hash_function;
		this.dbPath = dbPath;
	}

	private synchronized boolean verifyIntegrity(byte[] rcv_hash, String op_params, String op_type, long nonce) {
		String data = op_params + op_type + nonce;
		byte[] computed_hash = Cryptography.digest(hash_function, data.getBytes());

		return MessageDigest.isEqual(rcv_hash, computed_hash);
	}

	private synchronized <K,T> RestResponse processRequest(String auth_token, String access_token, String op_params, String op_type, long nonce, RequestHandler<AuthenticationToken, RestResponse> requestHandler) throws Exception {
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
	public synchronized RestResponse listFiles(String auth_token, String access_token, long nonce, String username, String path) throws Exception {
		System.out.println("nonce: " + nonce);
		return processRequest(auth_token, access_token, username+path, AccessControler.READ_ACCESS_REQUEST, nonce, (auth) -> {
			Path dirPath = buildPath(username, path);
			return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", listFiles(dirPath));
		});
	}

	@Override
	public synchronized RestResponse mkdir(String auth_token, String access_token, long nonce, String username, String path) throws Exception {
		return processRequest(auth_token, access_token, username+path, AccessControler.WRITE_ACCESS_REQUEST, nonce, (auth) -> {
			Path dirPath = buildPath(username, path);
			return new  RestResponse("1.0", Status.OK.getStatusCode(), "OK", new File(dirPath.toString()).mkdirs());
		});
	}

	@Override
	public synchronized RestResponse upload(String auth_token, String access_token, long nonce, String username, String path, byte[] data) throws Exception {
		return processRequest(auth_token, access_token, username+path+java.util.Base64.getEncoder().encodeToString(data), AccessControler.WRITE_ACCESS_REQUEST, nonce, (auth) -> {
			try {
				Path filePath = buildPath(username, path);
				Files.write(filePath, data);
				return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", true);

			} catch (IOException e) {
				return new RestResponse("1.0", Status.INTERNAL_SERVER_ERROR.getStatusCode(), Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), "IOException");
			}
		});
	}

	@Override
	public synchronized RestResponse download(String auth_token, String access_token, long nonce, String username, String path) throws Exception {
		return processRequest(auth_token, access_token, username+path, AccessControler.READ_ACCESS_REQUEST, nonce,  (auth) -> {
			try {
				Path filePath = buildPath(username, path);
				if(Files.exists(filePath) && Files.isReadable(filePath)) 
					return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", Files.readAllBytes(filePath));
			} catch (IOException e) { }

			return new RestResponse("1.0", Status.NOT_FOUND.getStatusCode(), Status.NOT_FOUND.getReasonPhrase(), "File not found");
		});
	}

	@Override
	public synchronized RestResponse copy(String auth_token, String access_token, long nonce, String username, String origin, String dest) throws Exception {
		return processRequest(auth_token, access_token, username+origin+dest, AccessControler.WRITE_ACCESS_REQUEST, nonce, (auth) -> {
			Path originPath = buildPath(username, origin);
			Path destPath = buildPath(username, dest);

			if(!Files.exists(originPath) || !Files.isReadable(originPath))
				return new RestResponse("1.0", Status.NOT_FOUND.getStatusCode(), Status.NOT_FOUND.getReasonPhrase(), origin + " not found!");

			try {
				Files.copy(originPath, destPath);
				return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", true);

			} catch (IOException e) {
				return new RestResponse("1.0", Status.INTERNAL_SERVER_ERROR.getStatusCode(), Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), "IOException");
			}
		});
	}

	@Override
	public synchronized RestResponse remove(String auth_token, String access_token, long nonce, String username, String path) throws Exception {
		return processRequest(auth_token, access_token, username+path, AccessControler.WRITE_ACCESS_REQUEST, nonce, (auth) -> {
			Path filePath = buildPath(username, path);
			try {
				return new RestResponse("1.0", Status.OK.getStatusCode(), "OK",  Files.deleteIfExists(filePath));
			} catch (IOException e) {
				return new RestResponse("1.0", Status.INTERNAL_SERVER_ERROR.getStatusCode(), Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), "IOException");
			}
		});
	}

	@Override
	public synchronized RestResponse removeDirectory(String auth_token, String access_token, long nonce, String username, String path) throws Exception {
		return processRequest(auth_token, access_token, username+path, AccessControler.WRITE_ACCESS_REQUEST, nonce, (auth) -> {
			Path dirPath = buildPath(username, path);
			if(listFiles(dirPath).size() > 0)
				return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", false);
			try {
				Files.delete(dirPath);
				return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", true);
			} catch (IOException e) {
				return new RestResponse("1.0", Status.INTERNAL_SERVER_ERROR.getStatusCode(), Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), "IOException");
			}
		});
	}

	@Override
	public synchronized RestResponse getFileMetadata(String auth_token, String access_token, long nonce, String username, String path) throws Exception {
		return processRequest(auth_token, access_token, username+path, AccessControler.READ_ACCESS_REQUEST, nonce, (auth) -> {
			Path filePath = buildPath(username, path);
			try {
				if(Files.exists(filePath)) {
					int idx = path.lastIndexOf(".");
					String ext =  idx > 0 ? path.substring(idx) : "-";
					BasicFileAttributes bfa =  Files.readAttributes(filePath, BasicFileAttributes.class);
					String metadata = String.format("%s\t%s\t%s\tCreated on: %s\tLast Access on: %s\n", path, bfa.isDirectory() ? "D" : "F", ext , new Date(bfa.creationTime().toMillis()), new Date( bfa.lastModifiedTime().toMillis()));
					return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", metadata);
				}
			}catch(IOException e){	
				return new RestResponse("1.0", Status.INTERNAL_SERVER_ERROR.getStatusCode(), Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), "IOException");
			}

			return new RestResponse("1.0", Status.NOT_FOUND.getStatusCode(), Status.NOT_FOUND.getReasonPhrase(), path + " not found!");
		});
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