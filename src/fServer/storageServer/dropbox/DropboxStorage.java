package fServer.storageServer.dropbox;

import java.io.IOException;
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

import fServer.storageServer.StorageImplementation;
import fServer.storageServer.StorageService;
import fServer.storageServer.dropbox.msgs.ListFolderContinueV2Args;
import fServer.storageServer.dropbox.msgs.ListFolderV2Args;
import fServer.storageServer.dropbox.msgs.ListFolderV2Return;
import rest.RestResponse;
import utility.JSON;

public class DropboxStorage extends DropboxClient implements StorageService {

	private static final String CREATE_FOLDER_V2_URL = "https://api.dropboxapi.com/2/files/create_folder_v2";
	private static final String UPLOAD_FILE_V2_URL = "https://content.dropboxapi.com/2/files/upload";
	private static final String DELETE_FILE_V2_URL = "https://api.dropboxapi.com/2/files/delete_v2";
	private static final String DOWNLOAD_FILE_V2_URL = "https://content.dropboxapi.com/2/files/download";
	private static final String LIST_FOLDER_V2_URL = "https://api.dropboxapi.com/2/files/list_folder";
	private static final String LIST_FOLDER_CONTINUE_V2_URL = "https://api.dropboxapi.com/2/files/list_folder/continue";
	private static final String MOVE_FOLDER_CONTINUE_V2_URL = "https://api.dropboxapi.com/2/files/move_batch";

	private static Logger logger = Logger.getLogger(DropboxStorage.class.toString());

	String root;

	public DropboxStorage(String root) {
		super();
		this.root = root;
	}

	/*
		@Override
		public void checkAndCreateDirectory(String dir) {
			OAuthRequest createFolder = new OAuthRequest(Verb.POST, CREATE_FOLDER_V2_URL);
			createFolder.addHeader("Content-Type", JSON_CONTENT_TYPE);

			createFolder.setPayload(JSON.encode(new CreateFolderV2Args(this.root + dir, false)));

			service.signRequest(accessToken, createFolder);

			try {
				Response r = service.execute(createFolder);

				if (r.isSuccessful()) {
					logger.log(Level.INFO, "Dropbox directory was created with success");
				} else {
					logger.log(Level.WARNING, "createFolder: Unexpected error HTTP: " + r.getCode() + "\n" + r.getBody());
				}
			} catch (InterruptedException | ExecutionException | IOException e) {
				e.printStackTrace();
			}
		}

		@Override
		public boolean writeBlock(String dir, String blockId, byte[] content) {

			String path = this.root + dir + "/" + blockId;

			OAuthRequest uploadFile = new OAuthRequest(Verb.POST, UPLOAD_FILE_V2_URL);
			uploadFile.addHeader("Content-Type", OCTET_STREAM_CONTENT_TYPE);
			uploadFile.addHeader("Dropbox-API-Arg", JSON.encode(new UploadFileV2Args(path, "overwrite", false, true)));

			uploadFile.setPayload(content);

			service.signRequest(accessToken, uploadFile);

			try {
				Response r = service.execute(uploadFile);

				if (r.getCode() == 200) {
					logger.log(Level.INFO, "Dropbox file was uploaded with success");
				} else {
					logger.log(Level.WARNING, "uploadFile: Unexpected error HTTP: " + r.getCode());
					throw new WebApplicationException(Status.CONFLICT);
				}
			} catch (InterruptedException | ExecutionException | IOException e) {
				e.printStackTrace();
				return false;
			}

			return true;
		}

		@Override
		public boolean deleteBlock(String dir, String blockId) {
			String path = this.root + dir + "/" + blockId;

			return delete(path);
		}

		@Override
		public byte[] readBlock(String dir, String blockId) {

			String path = this.root + dir + "/" + blockId;

			OAuthRequest downloadFile = new OAuthRequest(Verb.POST, DOWNLOAD_FILE_V2_URL);
			downloadFile.addHeader("Content-Type", OCTET_STREAM_CONTENT_TYPE);

			downloadFile.addHeader("Dropbox-API-Arg", JSON.encode(new DownloadFileV2Args(path)));

			service.signRequest(accessToken, downloadFile);

			try {
				Response r = service.execute(downloadFile);

				if (r.getCode() == 200) {
					logger.log(Level.INFO, "Dropbox file read with success");
					return r.getBody().getBytes();
				} else {
					logger.log(Level.WARNING, "readFile " + path + " : Unexpected error HTTP: " + r.getCode());
					throw new WebApplicationException(Status.NOT_FOUND);
				}

			} catch (InterruptedException | ExecutionException | IOException e) {
				e.printStackTrace();
				return null;
			}
		}

		@Override
		public List<String> listDirectory(String dir) {

			String path = this.root + dir;

			OAuthRequest listFolder = new OAuthRequest(Verb.POST, LIST_FOLDER_V2_URL);
			listFolder.addHeader("Content-Type", JSON_CONTENT_TYPE);
			listFolder.setPayload(JSON.encode(new ListFolderV2Args(path, true)));

			List<String> list = new LinkedList<>();

			for (;;) {
				service.signRequest(accessToken, listFolder);

				Response r;
				try {
					r = service.execute(listFolder);

					if (r.getCode() != 200)
						throw new RuntimeException("Failed: " + r.getMessage());

					ListFolderV2Return result = JSON.decode(r.getBody(), ListFolderV2Return.class);

					result.getEntries().forEach(e -> {
						if (e.isFile())
							list.add(e.getName());
					});

					if (result.has_more()) {
						System.err.println("continuing...");
						listFolder = new OAuthRequest(Verb.POST, LIST_FOLDER_CONTINUE_V2_URL);
						listFolder.addHeader("Content-Type", JSON_CONTENT_TYPE);
						listFolder.setPayload(JSON.encode(new ListFolderContinueV2Args(result.getCursor())));
					} else
						break;
				} catch (InterruptedException | ExecutionException | IOException e) {
					e.printStackTrace();
					throw new RuntimeException("Failed");
				}
			}

			return list;
		}

		@Override
		public boolean moveDirectory(String origin, String destiny) {
			OAuthRequest moveFolder = new OAuthRequest(Verb.POST, MOVE_FOLDER_CONTINUE_V2_URL);
			moveFolder.addHeader("Content-Type", JSON_CONTENT_TYPE);

			List<String> temp = this.listDirectory(origin);
			Entry[] entries = new Entry[temp.size()];
			int counter = 0;
			for(String s : temp ) {
				entries[counter++] = new Entry( this.root + origin + "/" + s, this.root + destiny + "/" + s);
			}

			moveFolder.setPayload(JSON.encode(new MoveFolderV2Args( entries )));

			service.signRequest(accessToken, moveFolder);

			try {
				Response r = service.execute(moveFolder);

				if (r.getCode() == 200) {
					logger.log(Level.INFO, "Dropbox file read with success");
					return true;
				} else {
					logger.log(Level.WARNING, "moveFiles  " + origin + " to " + destiny + " : Unexpected error HTTP: " + r.getCode());
					throw new WebApplicationException(Status.NOT_FOUND);
				}

			} catch (InterruptedException | ExecutionException | IOException e) {
				e.printStackTrace();
			}

			return false;
		}

		@Override
		public boolean deleteDirectory(String path) {
			return delete(this.root + path);
		}

		private boolean delete( String path ) {

			OAuthRequest deleteFile = new OAuthRequest(Verb.POST, DELETE_FILE_V2_URL);
			deleteFile.addHeader("Content-Type", JSON_CONTENT_TYPE);

			deleteFile.setPayload(JSON.encode(new DeleteFileV2Args(path)));

			service.signRequest(accessToken, deleteFile);

			try {
				Response r = service.execute(deleteFile);

				if (r.getCode() == 200) {
					logger.log(Level.INFO, "Dropbox file deleted with success");
					return true;
				} else {
					logger.log(Level.WARNING, "deleteFile " + path + " : Unexpected error HTTP: " + r.getCode() + "\n" + r.getBody());
					return false;
				}
			} catch (InterruptedException | ExecutionException | IOException e) {
				e.printStackTrace();
			}

			return false;
		}
	 */
	@Override
	public RestResponse listFiles(String token, String access_token, long nonce, String username, String path)
			throws Exception {


		String fullPath = this.root + StorageImplementation.buildPath(fullPath, fullPath) ;

		OAuthRequest listFolder = new OAuthRequest(Verb.POST, LIST_FOLDER_V2_URL);
		listFolder.addHeader("Content-Type", JSON_CONTENT_TYPE);
		listFolder.setPayload(JSON.encode(new ListFolderV2Args(path, true)));

		List<String> list = new LinkedList<>();

		for (;;) {
			service.signRequest(accessToken, listFolder);

			Response r;
			try {
				r = service.execute(listFolder);

				if (r.getCode() != 200)
					throw new RuntimeException("Failed: " + r.getMessage());

				ListFolderV2Return result = JSON.decode(r.getBody(), ListFolderV2Return.class);

				result.getEntries().forEach(e -> {
					if (e.isFile())
						list.add(e.getName());
				});

				if (result.has_more()) {
					System.err.println("continuing...");
					listFolder = new OAuthRequest(Verb.POST, LIST_FOLDER_CONTINUE_V2_URL);
					listFolder.addHeader("Content-Type", JSON_CONTENT_TYPE);
					listFolder.setPayload(JSON.encode(new ListFolderContinueV2Args(result.getCursor())));
				} else
					break;
			} catch (InterruptedException | ExecutionException | IOException e) {
				e.printStackTrace();
				throw new RuntimeException("Failed");
			}
		}

		return null;
	}

	@Override
	public RestResponse mkdir(String token, String access_token, long nonce, String username, String path)
			throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public RestResponse upload(String token, String access_token, long nonce, String username, String path, byte[] data)
			throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public RestResponse download(String token, String access_token, long nonce, String username, String path)
			throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public RestResponse copy(String token, String access_token, long nonce, String username, String src, String dest)
			throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public RestResponse remove(String token, String access_token, long nonce, String username, String path)
			throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public RestResponse removeDirectory(String token, String access_token, long nonce, String username, String path)
			throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public RestResponse getFileMetadata(String token, String access_token, long nonce, String username, String path)
			throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

}
