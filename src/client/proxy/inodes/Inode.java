package client.proxy.inodes;

public interface Inode {

	public void setParent(DirectoryInode parent);
	
	public String getName();
	
	public String getPath();
	
	public boolean isDirectory();
	
	public Inode getCurrentDirectory();
	
}
