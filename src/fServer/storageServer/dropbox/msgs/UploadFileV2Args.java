package fServer.storageServer.dropbox.msgs;

public class UploadFileV2Args {
	final String path;
	final String mode;
	final boolean autorename;
	final boolean mute;

	public UploadFileV2Args(String path, String mode, boolean autorename, boolean mute) {
		this.path = path;
		this.mode = mode;
		this.autorename = autorename;
		this.mute = mute;
	}
}