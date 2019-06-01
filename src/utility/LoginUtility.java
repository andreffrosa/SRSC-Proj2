package utility;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class LoginUtility {
	
	private String hash_algorithm;
	private String hash_algorithm_provider;
	
	private String pbe_algorithm;
	private String pbe_algorithm_provider;
	private int iterations;
	
	public LoginUtility(String hash_algorithm, String hash_algorithm_provider, String pbe_algorithm, String pbe_algorithm_provider, int iterations) {
		this.hash_algorithm = hash_algorithm;
		this.hash_algorithm_provider = hash_algorithm_provider;
		this.pbe_algorithm = pbe_algorithm;
		this.pbe_algorithm_provider = pbe_algorithm_provider;
		this.iterations = iterations;
	}
	
	public Cipher[] getCipherPair(String password, long salt) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchPaddingException {
        return Cryptography.genPBECiphers(password, ArrayUtil.longToBytes(salt), iterations, pbe_algorithm, pbe_algorithm_provider);
	}
	
	public MessageDigest getHash() throws NoSuchAlgorithmException, NoSuchProviderException {
		return MessageDigest.getInstance(this.hash_algorithm, this.hash_algorithm_provider);
	}

	public static LoginUtility fromConfig(String path) throws IOException {
		Properties login_properties = IO.loadProperties(path);
		String hash_algorithm = login_properties.getProperty("HASH-ALGORITHM");
		String hash_algorithm_provider = login_properties.getProperty("HASH-ALGORITHM-PROVIDER");
		
		String pbe_algorithm = login_properties.getProperty("PBE-ALGORITHM");
		String pbe_algorithm_provider = login_properties.getProperty("PBE-ALGORITHM-PROVIDER");
		int iterations = Integer.parseInt(login_properties.getProperty("ITERATIONS"));
		
		return new LoginUtility(hash_algorithm, hash_algorithm_provider, pbe_algorithm, pbe_algorithm_provider, iterations);
	}
	
}
