package client.proxy;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import client.exception.FileNotFoundException;
import client.exception.LogginRequieredException;
import client.exception.UnautorizedException;
import client.proxy.inodes.Directory;
import client.proxy.inodes.DirectoryInode;
import client.proxy.inodes.Inode;
import utility.Cryptography;

public class EncryptedFileSystem {

	private DirectoryInode root;

	public EncryptedFileSystem() {
		this.root = new Directory(""); // Root does not have a name
	}

	public List<String> listFiles(String path) throws FileNotFoundException {

		Inode i = this.root.getInode(path);

		if(i!= null) {
			if(i.isDirectory()) {
				return new ArrayList<>(((DirectoryInode)i).getChildren().keySet());
			}
		}

		throw new FileNotFoundException();
	}

	public String convertPath(String path) throws Exception {
		MessageDigest hash_function = MessageDigest.getInstance("SHA256");  // TODO:

		byte[] hash = Cryptography.digest(hash_function, path.getBytes());
		String s = java.util.Base64.getEncoder().encodeToString(hash);
		return s.replaceAll("/", "-");
	}

	public boolean mkdir(String path) {

		java.io.File f = new java.io.File(path);
		Inode i = this.root.getInode(f.getParent());

		if(i!= null) {
			if(i.isDirectory()) {
				((DirectoryInode)i).addChild(new Directory(f.getName()));
				return true;
			}
		}

		// TODO: o que fazer?*/
		return false;
	}

	public boolean upload(String path, byte[] data) {
		// TODO: Fazer upload para a cloud e criar as chaves, cifrar assinar e assim
		java.io.File f = new java.io.File(path);
		Inode i = this.root.getInode(f.getParent());

		if(i!= null) {
			if(i.isDirectory()) {
				((DirectoryInode)i).addChild(new client.proxy.inodes.File(f.getName()));
				return true;
			}
		}

		return false;
	}

	public byte[] download(String username, String path) throws FileNotFoundException {
		// TODO
		return null;
	}

	public boolean copy(String username, String origin, String dest) throws FileNotFoundException {
		// TODO
		return false;
	}

	public boolean remove(String username, String path) throws FileNotFoundException {
		// TODO
		return false;
	}

	public boolean removeDirectory(String path) throws FileNotFoundException {
		java.io.File f = new java.io.File(path);
		Inode i = this.root.getInode(f.getParent());

		if(i!= null) {
			if(i.isDirectory()) {
				DirectoryInode d = ((DirectoryInode)i);
				Inode a = d.getChildren().get(f.getName());
				if(a.isDirectory() && ((DirectoryInode)a).getChildren().isEmpty()) {
					d.removeChild(f.getName());
					return true;
				}
			}
		}

		return false;
	}

	public String getFileMetadata(String username, String path) throws FileNotFoundException {
		// TODO: Como fazer isto?
		return null;
	}

}
