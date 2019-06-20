package fServer.storageServer.dropbox.msgs;

public class CopyFileV2 {
	
	final String from_path;
	final String to_path;
	final boolean allow_shared_folder;
	final boolean autorename;
	final boolean allow_ownership_transfer;
	
	public CopyFileV2(String fromPath, String toPath, boolean allow_shared, boolean autorename, boolean allow_ownership_transfer) {
		this.from_path = fromPath;
		this.to_path = toPath;
		this.allow_shared_folder = allow_shared;
		this.autorename = autorename;
		this.allow_ownership_transfer = allow_ownership_transfer;
	}

}
