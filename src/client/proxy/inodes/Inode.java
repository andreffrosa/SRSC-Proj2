package client.proxy.inodes;

public interface Inode {

	public void setParent(DirectoryInode parent);
	
	public String getName();
	
	public String getPath();
	
	public boolean isDirectory();
	
	public DirectoryInode getParent();
	
	public long getCreatedTime();
	
	public long getLastAccess();
}
