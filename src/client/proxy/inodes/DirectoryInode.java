package client.proxy.inodes;

import java.util.Map;

public interface DirectoryInode extends Inode {

	public Map<String, Inode> getChildren();
	
	public void addChild(Inode inode);
	
	public Inode removeChild(String name);
	
	public Inode getInode(String path);
	
}
