import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;

import utility.Cryptography;
import utility.IO;

public class Temp {

	public static void main(String[] args) throws Exception {
		MessageDigest	hash = MessageDigest.getInstance("SHA512", "BC");
		
		String password = "larina";
		byte[] p_hash = Cryptography.digest(hash, password.getBytes());
		System.out.println(java.util.Base64.getEncoder().encodeToString(p_hash));
		
		hash.reset();
		
		password = "password";
		p_hash = Cryptography.digest(hash, password.getBytes());
		System.out.println(java.util.Base64.getEncoder().encodeToString(p_hash));
	
	}
}
