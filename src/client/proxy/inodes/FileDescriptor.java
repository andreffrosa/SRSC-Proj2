package client.proxy.inodes;

import javax.crypto.SecretKey;

public class FileDescriptor extends AbstractInode implements FileInode {

	private FragmentMetaData[] fragments;
	
	public FileDescriptor(String name, FragmentMetaData[] fragments) {
		super(name);
		this.fragments = fragments;
	}

	@Override
	public boolean isDirectory() {
		return false;
	}

	public FragmentMetaData[] getFragmentsMetaData() {
		this.last_access = System.currentTimeMillis();
		return fragments;
	}
	
	public static class FragmentMetaData {
		public String name;
		public SecretKey ks;
		public byte[] iv;
		
		public FragmentMetaData(String name, SecretKey ks, byte[] iv) {
			this.name = name;
			this.ks = ks;
			this.iv = iv;
		}
	}

}
