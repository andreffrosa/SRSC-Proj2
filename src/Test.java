

import java.util.Map.Entry;

import client.proxy.EncryptedFileSystem;
import client.proxy.inodes.Directory;
import client.proxy.inodes.DirectoryInode;
import client.proxy.inodes.Inode;

public class Test {

	public static void main(String[] args) throws Exception {
		/*DirectoryInode root = new Directory(""); // Root does not have a name
		DirectoryInode homework = new Directory("homework");
		root.addChild(homework);
		root.addChild(new Directory("Desktop"));
		
		homework.addChild(new Directory("math"));*/
		
	/*	for(Entry<String, Inode> e : homework.getChildren().entrySet()) {
			System.out.println(e.getValue().getPath());
		}*/
		
		/*Inode i = root.getInode("/homework/math/");
		System.out.println(i.getName());*/
		
		EncryptedFileSystem fs = new EncryptedFileSystem();
		/*for(String s : fs.listFiles("/homework/")) {
			System.out.println(s);
		}*/
		
		fs.mkdir("/larina/");
		fs.mkdir("/homework/");
		for(String s : fs.listFiles("/")) {
			System.out.println(s);
		}
		System.out.println("");
		fs.removeDirectory("/larina/");
		for(String s : fs.listFiles("/")) {
			System.out.println(s);
		}
		System.out.println("");
		
		System.out.println(fs.convertPath("/larina/"));
		
		
	}

}
