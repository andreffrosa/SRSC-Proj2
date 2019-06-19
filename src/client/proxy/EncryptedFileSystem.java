package client.proxy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import client.exception.FileNotFoundException;
import client.proxy.inodes.DataFragment;
import client.proxy.inodes.Directory;
import client.proxy.inodes.DirectoryInode;
import client.proxy.inodes.FileDescriptor;
import client.proxy.inodes.FileDescriptor.FragmentMetaData;
import client.proxy.inodes.Inode;
import utility.Cryptography;

public class EncryptedFileSystem {

	private String secret_key_gen_algorithm;
	private String secret_key_gen_provider;
	private int secret_key_size;
	private int iv_size;
	private String cipher_algorithm;
	private String cipher_provider;
	
	private Signature sig;
	private KeyPair myKeyPair;
	private MessageDigest hash_function;
	private SecureRandom sr;
	
	private DirectoryInode root;
	private int fragment_size;
	private int encrypted_payload_size;

	public EncryptedFileSystem(int fragment_size, String secret_key_gen_algorithm, String secret_key_gen_provider, int secret_key_size,
			int iv_size, String cipher_algorithm, String cipher_provider, Signature sig, KeyPair myKeyPair,
			MessageDigest hash_function, SecureRandom sr) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		this.root = new Directory(""); // Root does not have a name
		this.hash_function = hash_function;
		this.fragment_size = fragment_size;
		
		this.secret_key_gen_algorithm = secret_key_gen_algorithm;
		this.secret_key_gen_provider = secret_key_gen_provider;
		this.secret_key_size = secret_key_size;
		this.iv_size = iv_size;
		this.cipher_algorithm = cipher_algorithm;
		this.cipher_provider = cipher_provider;
		this.sig = sig;
		this.myKeyPair = myKeyPair;
		this.hash_function = hash_function;
		this.sr = sr;
		
		// TODO: Discover a smartest way to do this
		SecretKey ks = Cryptography.generateSecretKey(this.secret_key_gen_algorithm, this.secret_key_gen_provider, this.secret_key_size);
		byte[] iv = Cryptography.createIV(sr, this.iv_size);
		this.encrypted_payload_size = getCipher(ks, iv, Cipher.ENCRYPT_MODE).getOutputSize(fragment_size);
	}
	
	private Cipher getCipher(SecretKey ks, byte[] iv, int mode) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {
		if(this.cipher_provider != null)
			return Cryptography.buildCipher(this.cipher_algorithm, mode, ks, iv, this.cipher_provider);
		else
			return Cryptography.buildCipher(this.cipher_algorithm, mode, ks, iv);
	}

	public String convertPath(String path) {
		byte[] hash = Cryptography.digest(hash_function, path.getBytes());
		String s = java.util.Base64.getEncoder().encodeToString(hash);
		return s.replaceAll("/", "-");
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

	public DataFragment[] write(String path, byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, SignatureException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, IOException {
		java.io.File f = new java.io.File(path);
		Inode i = this.root.getInode(f.getParent());

		if(i!= null) {
			if(i.isDirectory()) {
				int n_fragments = DataFragment.getNfragments(data.length, fragment_size);
				
				FragmentMetaData[] fragments_meta = new FragmentMetaData[n_fragments];
				String[] names = new String[n_fragments];
				Cipher[] ciphers = new Cipher[n_fragments];
				
				for(int j = 0; j < n_fragments; j++) {
					SecretKey ks = Cryptography.generateSecretKey(this.secret_key_gen_algorithm, this.secret_key_gen_provider, this.secret_key_size);
					byte[] iv = Cryptography.createIV(sr, this.iv_size);
					
					ciphers[j] =  getCipher(ks, iv, Cipher.ENCRYPT_MODE);
					
					names[j] = this.convertPath(path + ".fragment-" + j);
					
					fragments_meta[j] = new client.proxy.inodes.FileDescriptor.FragmentMetaData(names[j], ks, iv);
				}
				DataFragment[] fragments = DataFragment.fragment(data, fragment_size, names, ciphers, sig, myKeyPair.getPrivate(), sr);
				
				((DirectoryInode)i).addChild(new client.proxy.inodes.FileDescriptor(f.getName(), fragments_meta));
				
				return fragments;
			}
		}

		return null; // TODO Throw uma excepção qualquer
	}

	public client.proxy.inodes.FileDescriptor getFileDescriptor(String path) throws FileNotFoundException {
		Inode i = this.root.getInode(path);

		if(i!= null) {
			if(!i.isDirectory()) {
				client.proxy.inodes.FileDescriptor fd = (FileDescriptor) i;
				return fd;
			}
		}

		throw new FileNotFoundException();
	}
	
	public byte[] assemble(client.proxy.inodes.FileDescriptor fd, byte[][] raw_fragments) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IOException {
		
		FragmentMetaData[] meta = fd.getFragmentsMetaData();
		
		DataFragment[] fragments = new DataFragment[meta.length];
		
		for(int i = 0; i < meta.length; i++) {
			Cipher decryptCipher = getCipher(meta[i].ks, meta[i].iv, Cipher.DECRYPT_MODE);
			fragments[i] = DataFragment.deserialize(meta[i].name, raw_fragments[i], encrypted_payload_size, decryptCipher);
		}
		
		return DataFragment.defragment(fragments);
	}

	public Map<String, String> copy(String origin, String dest) throws FileNotFoundException {
		FileDescriptor fd = this.getFileDescriptor(origin);
		
		java.io.File f = new java.io.File(dest);
		DirectoryInode i = (DirectoryInode) this.root.getInode(f.getParent());

		if(i!= null) {
			if(i.isDirectory()) {
				FragmentMetaData[] origin_fragments_meta = fd.getFragmentsMetaData();
				int n_fragments = origin_fragments_meta.length;
				
				FragmentMetaData[] fragments_meta = new FragmentMetaData[n_fragments];
				
				Map<String, String> copies = new HashMap<>(n_fragments);
				
				for(int j = 0; j < n_fragments; j++) {
					SecretKey ks = origin_fragments_meta[j].ks;
					byte[] iv = origin_fragments_meta[j].iv;
					
					String name = this.convertPath(dest + ".fragment-" + j);
					
					fragments_meta[j] = new client.proxy.inodes.FileDescriptor.FragmentMetaData(name, ks, iv);
					
					copies.put(origin_fragments_meta[j].name, name);
				}

				i.addChild(new client.proxy.inodes.FileDescriptor(f.getName(), fragments_meta));
				
				return copies;
			}
		}
		
		return null; // TODO: O que fazer?
	}

	public boolean remove(String path) throws FileNotFoundException {

		FileDescriptor fd = this.getFileDescriptor(path);
		fd.getParent().removeChild(fd.getName());

		return true;
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

	public String getFileMetadata(String path) throws FileNotFoundException {
		
		int idx = path.lastIndexOf(".");
		String ext =  idx > 0 ? path.substring(idx) : "-";
		
		Inode i = this.root.getInode(path);
		
		String metadata = String.format("%s\t%s\t%s\tCreated on: %s\tLast Access on: %s\n", path, i.isDirectory() ? "D" : "F", ext , new Date(i.getCreatedTime()), new Date(i.getLastAccess()));
		
		return metadata;
	}

}