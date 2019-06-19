package client.proxy.inodes;

import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

public abstract class AbstractInode implements Inode {

	protected DirectoryInode parent;
	protected String name;
	protected long create_time;
	protected long last_access;

	public AbstractInode(String name) {
		this.name = name;
		this.create_time = System.currentTimeMillis();
		this.last_access = this.create_time;
	}

	@Override
	public void setParent(DirectoryInode parent) {
		this.parent = parent;
	}

	@Override
	public DirectoryInode getParent() {
		return parent;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getPath() {
		this.last_access = System.currentTimeMillis();
		String d = (this.isDirectory() ? "/" : "");
		return (parent == null ? "" : parent.getPath() + d) + this.name + d;
	}

	@Override
	public long getCreatedTime() {
		return this.create_time;
	}
	
	@Override
	public long getLastAccess() {
		return this.last_access;
	}
	
}
