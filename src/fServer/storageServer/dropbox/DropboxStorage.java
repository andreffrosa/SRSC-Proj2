package fServer.storageServer.dropbox;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response.Status;

import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;

import fServer.accessControlServer.AccessControler;
import fServer.storageServer.dropbox.msgs.CopyFileV2;
import fServer.storageServer.dropbox.msgs.CreateFolderV2Args;
import fServer.storageServer.dropbox.msgs.DeleteFileV2Args;
import fServer.storageServer.dropbox.msgs.DownloadFileV2Args;
import fServer.storageServer.dropbox.msgs.ListFolderContinueV2Args;
import fServer.storageServer.dropbox.msgs.ListFolderV2Args;
import fServer.storageServer.dropbox.msgs.ListFolderV2Return;
import fServer.storageServer.dropbox.msgs.UploadFileV2Args;
import rest.RestResponse;
import token.TokenVerifier;
import utility.JSON;

public class DropboxStorage extends StorageDropboxClient{

	private static final String CONTENT_TYPE = "Content-Type";
	private static final String CREATE_FOLDER_V2_URL = "https://api.dropboxapi.com/2/files/create_folder_v2";
	private static final String UPLOAD_FILE_V2_URL = "https://content.dropboxapi.com/2/files/upload";
	private static final String DELETE_FILE_V2_URL = "https://api.dropboxapi.com/2/files/delete_v2";
	private static final String DOWNLOAD_FILE_V2_URL = "https://content.dropboxapi.com/2/files/download";
	private static final String LIST_FOLDER_V2_URL = "https://api.dropboxapi.com/2/files/list_folder";
	private static final String LIST_FOLDER_CONTINUE_V2_URL = "https://api.dropboxapi.com/2/files/list_folder/continue";
	private static final String COPY_FILE_V2_URL = "https://api.dropboxapi.com/2/files/copy_v2";

	private static Logger logger = Logger.getLogger(DropboxStorage.class.toString());

	String root;

	public DropboxStorage(String cloudProvider, String root, TokenVerifier authTokenVerifier, TokenVerifier accessTokenVerifier, MessageDigest hash_function) {
		super(cloudProvider, authTokenVerifier, accessTokenVerifier, hash_function);
		this.root = root;
	}

	@Override
	public RestResponse listFiles(String auth_token, String access_token, long nonce, String username, String path)	throws Exception {

		return processRequest(auth_token, access_token, username+path, AccessControler.READ_ACCESS_REQUEST, nonce, (auth) -> {
			return list(username, path);
		});
	}

	@Override
	public RestResponse mkdir(String auth_token, String access_token, long nonce, String username, String path)	throws Exception {
		return processRequest(auth_token, access_token, username+path, AccessControler.WRITE_ACCESS_REQUEST, nonce, (auth) -> {

			String fullPath = "/"+root+"/"+username+path;
			
			OAuthRequest createFolder = new OAuthRequest(Verb.POST, CREATE_FOLDER_V2_URL);
			createFolder.addHeader(CONTENT_TYPE, JSON_CONTENT_TYPE);
			createFolder.setPayload(JSON.encode(new CreateFolderV2Args(fullPath, false)));

			service.signRequest(accessToken, createFolder);

			try {
				Response r = service.execute(createFolder);

				if (r.isSuccessful()) {
					logger.log(Level.INFO, "Dropbox directory was created with success");
					return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", true);
				} else {
					logger.log(Level.WARNING, "createFolder: Unexpected error HTTP: " + r.getCode() + "\n" + r.getBody());
				}
			} catch (InterruptedException | ExecutionException | IOException e) {
				e.printStackTrace();
			}

			return new RestResponse("1.0", Status.INTERNAL_SERVER_ERROR.getStatusCode(), "UnexepctedError", null);
		});
	}

	@Override
	public RestResponse upload(String auth_token, String access_token, long nonce, String username, String path, byte[] data)
			throws Exception {

		return processRequest(auth_token, access_token, username+path+java.util.Base64.getEncoder().encodeToString(data), AccessControler.WRITE_ACCESS_REQUEST, nonce, (auth) -> {

			String fullPath = "/"+root+"/"+username+path;

			OAuthRequest uploadFile = new OAuthRequest(Verb.POST, UPLOAD_FILE_V2_URL);
			uploadFile.addHeader("Content-Type", OCTET_STREAM_CONTENT_TYPE);
			uploadFile.addHeader("Dropbox-API-Arg", JSON.encode(new UploadFileV2Args(fullPath, "overwrite", false, true)));

			uploadFile.setPayload(data);

			service.signRequest(accessToken, uploadFile);

			try {
				Response r = service.execute(uploadFile);

				if (r.getCode() == 200) {
					logger.log(Level.INFO, "Dropbox file was uploaded with success");

				} else {
					logger.log(Level.WARNING, "uploadFile: Unexpected error HTTP: " + r.getCode()+ " " + r.getBody());
					throw new WebApplicationException(Status.CONFLICT);
				}
			} catch (InterruptedException | ExecutionException | IOException e) {
				e.printStackTrace();
				return new RestResponse("1.0", Status.INTERNAL_SERVER_ERROR.getStatusCode(), "ERROR", null);
			}

			return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", true);
		});
	}

	@Override
	public RestResponse download(String auth_token, String access_token, long nonce, String username, String path) throws Exception {

		return processRequest(auth_token, access_token, username+path, AccessControler.READ_ACCESS_REQUEST, nonce, (auth) -> {

			String fullPath = "/"+root+"/"+username+path;

			OAuthRequest downloadFile = new OAuthRequest(Verb.POST, DOWNLOAD_FILE_V2_URL);
			downloadFile.addHeader("Content-Type", OCTET_STREAM_CONTENT_TYPE);
			downloadFile.addHeader("Dropbox-API-Arg", JSON.encode(new DownloadFileV2Args(fullPath)));

			service.signRequest(accessToken, downloadFile);

			try {
				Response r = service.execute(downloadFile);

				if (r.getCode() == 200) {
					logger.log(Level.INFO, "Dropbox file read with success");
					return  new RestResponse("1.0", Status.OK.getStatusCode(), "OK", r.getBody().getBytes());
				} else {
					logger.log(Level.WARNING, "readFile " + path + " : Unexpected error HTTP: " + r.getCode());
					return new RestResponse("1.0", Status.NOT_FOUND.getStatusCode(), "Not Found", null);
				}

			} catch (InterruptedException | ExecutionException | IOException e) {
				e.printStackTrace();
				return new RestResponse("1.0", Status.INTERNAL_SERVER_ERROR.getStatusCode(), "Error", null);
			}
		});
	}

	@Override
	public RestResponse copy(String auth_token, String access_token, long nonce, String username, String src, String dest) throws Exception {

		return processRequest(auth_token, access_token, username+src+dest, AccessControler.WRITE_ACCESS_REQUEST, nonce, (auth) -> {

			String srcPath = "/"+root+"/"+username+src;
			String destPath = "/"+root+"/"+username+dest;

			OAuthRequest copyFile = new OAuthRequest(Verb.POST, COPY_FILE_V2_URL);
			copyFile.addHeader("Content-Type", JSON_CONTENT_TYPE);
			copyFile.setPayload(JSON.encode(new CopyFileV2(srcPath, destPath, false, true, false)));

			service.signRequest(accessToken, copyFile);

			try {
				Response r = service.execute(copyFile);

				if (r.getCode() == 200) {
					logger.log(Level.INFO, "Dropbox file was cpied with success");			
				} else {
					logger.log(Level.WARNING, "uploadFile: Unexpected error HTTP: " + r.getCode()+ " " + r.getBody() );
					return new RestResponse("1.0", Status.CONFLICT.getStatusCode(), "Conflict", null);
				}
			} catch (InterruptedException | ExecutionException | IOException e) {
				e.printStackTrace();
				return new RestResponse("1.0", Status.INTERNAL_SERVER_ERROR.getStatusCode(), "ERROR", null);
			}

			return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", true);
		});

	}

	@Override
	public RestResponse remove(String auth_token, String access_token, long nonce, String username, String path)	throws Exception {
		
		String fullPath = "/"+root+"/"+username+path;
		return delete(auth_token, access_token, nonce, fullPath);

	}

	@SuppressWarnings("unchecked")
	@Override
	public RestResponse removeDirectory(String auth_token, String access_token, long nonce, String username, String path) throws Exception {
	
		return processRequest(auth_token, access_token, username+path, AccessControler.WRITE_ACCESS_REQUEST, nonce, (auth) -> {
			
			String fullPath = "/"+root+"/"+username+path;
			List<String> contents = null;
			RestResponse listResponse = list(username, path);

			if (listResponse.getStatusCode() == Status.OK.getStatusCode()) { 
				contents =  (List<String>) listResponse.getEntity(List.class);
				if(contents.size() > 0)
					return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", false);
				else
					return delete(auth_token, access_token, nonce, fullPath);
			}else
				return new RestResponse("1.0", Status.INTERNAL_SERVER_ERROR.getStatusCode(), Status.INTERNAL_SERVER_ERROR.getReasonPhrase(), "IOException");
		
		});
	}


	@Override
	public RestResponse getFileMetadata(String token, String access_token, long nonce, String username, String path)
			throws Exception {		
		//Dropbox doesn't support this operation.
		return null;
	}

	private RestResponse delete( String auth_token, String access_token, long nonce, String fullPath ) throws Exception {

		OAuthRequest deleteFile = new OAuthRequest(Verb.POST, DELETE_FILE_V2_URL);
		deleteFile.addHeader("Content-Type", JSON_CONTENT_TYPE);
		deleteFile.setPayload(JSON.encode(new DeleteFileV2Args(fullPath)));

		service.signRequest(accessToken, deleteFile);

		try {
			Response r = service.execute(deleteFile);

			if (r.getCode() == 200) {
				logger.log(Level.INFO, "Dropbox file deleted with success");
				return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", true);
			} else {
				logger.log(Level.WARNING, "deleteFile " + fullPath + " : Unexpected error HTTP: " + r.getCode() + "\n" + r.getBody());
				return new RestResponse("1.0", r.getCode(), "Error", null);
			}
		} catch (InterruptedException | ExecutionException | IOException e) {
			e.printStackTrace();
		}

		return new RestResponse("1.0", Status.INTERNAL_SERVER_ERROR.getStatusCode(), "Error", null);
	}

	private RestResponse list(String username, String path) {

		String fullPath = "/"+root+"/"+username+path;

		OAuthRequest listFolder = new OAuthRequest(Verb.POST, LIST_FOLDER_V2_URL);
		listFolder.addHeader(CONTENT_TYPE, JSON_CONTENT_TYPE);
		listFolder.setPayload(JSON.encode(new ListFolderV2Args(fullPath, true)));

		List<String> list = new LinkedList<>();

		for (;;) {

			service.signRequest(this.accessToken, listFolder);
			Response r;

			try {
				r = service.execute(listFolder);

				if (r.getCode() != 200) {
					System.out.println("Error " + r.getCode() +" " +r.getMessage() + " " + r.getBody());
					throw new RuntimeException("Failed: " + r.getMessage());
				}

				ListFolderV2Return result = JSON.decode(r.getBody(), ListFolderV2Return.class);

				result.getEntries().forEach(e -> {
					if (e.isFile())
						list.add(e.getName());
				});

				if (result.has_more()) {
					System.err.println("continuing...");
					listFolder = new OAuthRequest(Verb.POST, LIST_FOLDER_CONTINUE_V2_URL);
					listFolder.addHeader(CONTENT_TYPE, JSON_CONTENT_TYPE);
					listFolder.setPayload(JSON.encode(new ListFolderContinueV2Args(result.getCursor())));
				} else
					break;
			} catch (InterruptedException | ExecutionException | IOException e) {
				e.printStackTrace();
				throw new RuntimeException("Failed");
			}
		}

		return new RestResponse("1.0", Status.OK.getStatusCode(), "OK", list);
	}

}
