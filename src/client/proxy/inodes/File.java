package client.proxy.inodes;

public class File extends AbstractInode implements FileInode {

	
	
	public File(String name) {
		super(name);
		// TODO Auto-generated constructor stub
	}

	@Override
	public boolean isDirectory() {
		return false;
	}

}
