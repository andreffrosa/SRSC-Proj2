package fServer.storageServer.dropbox.msgs;

public class CopyFileV2 {
	
	final String fromPath;
	final String toPath;
	final boolean allow_shared;
	final boolean autorename;
	final boolean allow_ownership_transfer;
	
	public CopyFileV2(String fromPath, String toPath, boolean allow_shared, boolean autorename, boolean allow_ownership_transfer) {
		this.fromPath = fromPath;
		this.toPath = toPath;
		this.allow_shared = allow_shared;
		this.autorename = autorename;
		this.allow_ownership_transfer = allow_ownership_transfer;
	}

}
