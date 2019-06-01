import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import utility.Cryptography;
import utility.IO;

public class Temp {

	public static void main(String[] args) throws Exception {
		/*MessageDigest	hash = MessageDigest.getInstance("SHA512", "BC");
		
		String password = "larina";
		byte[] p_hash = Cryptography.digest(hash, password.getBytes());
		System.out.println(java.util.Base64.getEncoder().encodeToString(p_hash));
		
		hash.reset();
		
		password = "password";
		p_hash = Cryptography.digest(hash, password.getBytes());
		System.out.println(java.util.Base64.getEncoder().encodeToString(p_hash));**/

		
		// NO PBE tem de se iniciar a cifra com o algoritmo de PBE?
	}
}
