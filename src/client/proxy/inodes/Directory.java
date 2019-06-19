package client.proxy.inodes;

import java.util.HashMap;
import java.util.Map;

public class Directory extends AbstractInode implements DirectoryInode {

	Map<String, Inode> children;

	public Directory(String name) {
		super(name);
		this.children = new HashMap<String, Inode>();
	}

	@Override
	public boolean isDirectory() {
		return true;
	}

	@Override
	public Map<String, Inode> getChildren() {
		this.last_access = System.currentTimeMillis();
		return children;
	}

	@Override
	public void addChild(Inode inode) {
		// TODO: Verificar se já existe?
		children.put(inode.getName(), inode);

		inode.setParent(this);
		
		this.last_access = System.currentTimeMillis();
	}

	@Override
	public Inode getInode(String path) {
		String[] s = path.split("/");
		DirectoryInode d = this;

		if(d.getPath().equals(path))
			return d;
		else {
			for(int i = 1; i < s.length-1; i++) {
				d = (DirectoryInode) d.getChildren().get(s[i]);
			}
			
			AbstractInode i =  (AbstractInode) d.getChildren().get(s[s.length-1]);
            i.last_access = System.currentTimeMillis();
			return i;
		}
	}

	@Override
	public Inode removeChild(String name) {
		this.last_access = System.currentTimeMillis();
		return children.remove(name);
	}

}
