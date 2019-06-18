package fServer.storageServer.dropbox.msgs;

public class MoveFolderV2Args {
	final Entry[] entries;
	final boolean allow_shared_folder;
	final boolean autorename;
	final boolean allow_ownership_transfer;
	
	public MoveFolderV2Args(Entry[] entries ) {

		this.entries = entries;
		this.allow_shared_folder = false;
	    this.autorename = false;
	    this.allow_ownership_transfer = false;

	}	
	
	public static class Entry {
		final String from_path;
		final String to_path;
		
		public Entry(String from_path, String to_path) {
			this.from_path = from_path;
			this.to_path = to_path;
		}

	}
}
