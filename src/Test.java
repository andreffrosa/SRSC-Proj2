

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import client.proxy.EncryptedFileSystem;
import client.proxy.inodes.DataFragment;
import client.proxy.inodes.Directory;
import client.proxy.inodes.DirectoryInode;
import client.proxy.inodes.FileDescriptor;
import client.proxy.inodes.Inode;
import utility.ArrayUtil;
import utility.Cryptography;
import utility.MyKeyStore;

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

		/*for(String s : fs.listFiles("/homework/")) {
			System.out.println(s);
		}*/

		/*fs.mkdir("/larina/");
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

		System.out.println(fs.convertPath("/larina/"));*/
		
		/*byte[]	keyBytes = new byte[] { 
				0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef, 
				0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef, 
				0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef ,
				0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef
		}; // 256 bit key
		SecretKey ks = new SecretKeySpec(keyBytes, "AES");
		byte[] iv = Cryptography.createIV(16);
		Cipher encryptCipher = Cryptography.buildCipher("AES/CBC/PKCS5Padding", Cipher.ENCRYPT_MODE, ks, iv);
		Cipher decryptCipher = Cryptography.buildCipher("AES/CBC/PKCS5Padding", Cipher.DECRYPT_MODE, ks, iv);
		
		Signature sig = Signature.getInstance("SHA512withRSA");
		SecureRandom sr = SecureRandom.getInstance("sha1PRNG");*/
		//DataFragment[] fragments = DataFragment.fragment(data, payload_size, encryptCipher, sig, privKey, sr);

		//for(DataFragment f : fragments) {
			//System.out.println(java.util.Base64.getEncoder().encodeToString(f.serialize()));
			/*System.out.println(new String(f.getData()));
			System.out.println("");
			System.out.println(java.util.Base64.getEncoder().encodeToString(f.getPadding()));
			System.out.printf("data: %d padding : %d payload: %d signature: %d \n", f.getData().length, f.getPadding().length, f.getPayload().length, f.getSignature().length);
		}*/
		
		/*byte[] data2 = new byte[0];
		for(DataFragment f : fragments) {
			DataFragment f2 = DataFragment.deserialize(f.serialize(), encryptCipher.getOutputSize(payload_size), decryptCipher);
			System.out.printf("data: %d padding : %d payload: %d signature: %d \n", f2.getData().length, f2.getPadding().length, f2.getPayload().length, f2.getSignature().length);
			
			System.out.println(MessageDigest.isEqual(f.getData(), f2.getData()));
			
			data2 = ArrayUtil.concat(data2, f2.getData());
		}

		System.out.println(MessageDigest.isEqual(data, data2));*/
		
		MessageDigest hash_function = MessageDigest.getInstance("SHA-256");
		Signature sig = Signature.getInstance("SHA512withRSA");
		SecureRandom sr = SecureRandom.getInstance("sha1PRNG");
		KeyPairGenerator generator= KeyPairGenerator.getInstance("RSA", "BC");
		KeyPair pair = generator.generateKeyPair();
		PublicKey pubKey= pair.getPublic();
		PrivateKey privKey= pair.getPrivate();

		byte[] data = ("Ya bina, não destina\n" + "Ya bina, não destina\n" + "Ya bina, não destina\n" + "Ya bina, não destina\n" + "Ya bina, não destina\n" + "Ya bina, não destina\n" + "Ya bina, não destina\n").getBytes();
		int fragment_size = 64;
		
		EncryptedFileSystem fs = new EncryptedFileSystem(fragment_size, "AES", "BC", 128, 16, "AES/CBC/PKCS5Padding", "BC", sig, pair, hash_function, sr);
		
		DataFragment[] frags = fs.write("/file1.txt", data);
		FileDescriptor fd = fs.getFileDescriptor("/file1.txt");
		
		byte[][] raw_fragments = new byte[fd.getFragmentsMetaData().length][];
		for(int i = 0; i < frags.length; i++) {
			raw_fragments[i] = frags[i].serialize();
		}
		byte[] data2 = fs.assemble(fd, raw_fragments);
		
		System.out.println(MessageDigest.isEqual(data, data2));
		
		/*Map<String, String> map = fs.copy("/file1.txt", "/file2.txt");
		
		for(Entry<String, String> m : map.entrySet()) {
			System.out.println(m.getKey() + " -> " + m.getValue());
		}
		
		fd = fs.getFileDescriptor("/file2.txt");
		raw_fragments = new byte[fd.getFragmentsMetaData().length][];
		for(int i = 0; i < frags.length; i++) {
			raw_fragments[i] = frags[i].serialize();
		}
		data2 = fs.assemble(fd, raw_fragments);
		
		System.out.println(MessageDigest.isEqual(data, data2));*/
		
	}

}
