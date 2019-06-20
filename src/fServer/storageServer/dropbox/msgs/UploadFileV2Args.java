package fServer.storageServer.dropbox.msgs;

public class UploadFileV2Args {
	final String path;
	final String mode;
	final boolean autorename;
	final boolean mute;
	final boolean strict_conflict;

	public UploadFileV2Args(String path, String mode, boolean autorename, boolean mute) {
		this.path = path;
		this.mode = mode;
		this.autorename = autorename;
		this.mute = mute;
		this.strict_conflict = false;
	}
}