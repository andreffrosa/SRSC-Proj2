package client.proxy.inodes;

public abstract class AbstractInode implements Inode {

	protected Inode parent;
	protected String name;
	
	public AbstractInode(String name) {
		this.name = name;
	}
	
	@Override
	public void setParent(DirectoryInode parent) {
		this.parent = parent;
	}

	@Override
	public Inode getCurrentDirectory() {
		return parent;
	}

	@Override
	public String getName() {
		return name;
	}
	
	@Override
	public String getPath() {
		String d = (this.isDirectory() ? "/" : "");
		return (parent == null ? "" : parent.getPath() + d) + this.name + d;
	}
	
}
