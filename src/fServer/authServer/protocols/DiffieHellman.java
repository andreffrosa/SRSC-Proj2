package fServer.authServer.protocols;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Properties;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import utility.IO;

public class DiffieHellman {

	private static final String DH_ALGORITHM = "DH";
	private static final String DEFAULT_PROVIDER = "BC";

	private static final String DEFAULT_SECURE_RANDOM = "sha1PRNG";

	private static final String DEFAULT_SECRET_KEY_ALGORITHM = "AES";
	private static final int DEFAULT_SECRET_KEY_SIZE = 16;


	private DHParameterSpec dhParams;
	private int secret_key_size;
	private String provider;
	private String secret_key_algorithm;
	private SecureRandom sr;

	public DiffieHellman(BigInteger p, BigInteger g) throws NoSuchAlgorithmException, NoSuchProviderException {
		this(p, g, DEFAULT_SECRET_KEY_SIZE, 
				DEFAULT_SECRET_KEY_ALGORITHM, DEFAULT_PROVIDER, 
				SecureRandom.getInstance(DEFAULT_SECURE_RANDOM, DEFAULT_PROVIDER));
	}
	
	public DiffieHellman(BigInteger p, BigInteger g, int secret_key_size, String secret_key_algorithm, String provider, SecureRandom sr) {
		this.dhParams = new DHParameterSpec(p, g);
		this.provider = provider;
		this.secret_key_size = secret_key_size;
		this.secret_key_algorithm = secret_key_algorithm;
		this.sr = sr;
	}

	public DHParameterSpec getParams() {
		return dhParams;
	}
	
	public SecureRandom getSecureRandom() {
		return sr;
	}
	
	public int getSecret_key_size() {
		return secret_key_size;
	}

	public String getProvider() {
		return provider;
	}

	public String getSecret_key_algorithm() {
		return secret_key_algorithm;
	}

	public KeyFactory getKeyFactory() throws NoSuchAlgorithmException, NoSuchProviderException {
		return KeyFactory.getInstance(DH_ALGORITHM, this.provider);
	}
	
	public KeyPair genKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(DH_ALGORITHM, this.provider);

		keyGen.initialize(dhParams, sr);

		KeyPair kp = keyGen.generateKeyPair();

		return kp;
	}

	public SecretKey establishSecretKey(PrivateKey myPrivKey, PublicKey peerPubKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
		KeyAgreement keyAgree = KeyAgreement.getInstance(DH_ALGORITHM, this.provider);

		keyAgree.init(myPrivKey, sr);

		keyAgree.doPhase(peerPubKey, true);

		byte[] secret = keyAgree.generateSecret();
		SecretKey ks = new SecretKeySpec(secret, 0, secret_key_size, secret_key_algorithm);

		return ks;
	}
	
	public static DiffieHellman buildDH(String dh_config_file) throws NoSuchAlgorithmException, IOException {
		Properties properties = IO.loadProperties(dh_config_file);
		
		String g_value = properties.getProperty("G");
		int g_radix = Integer.parseInt(properties.getProperty("G-RADIX"));
		BigInteger g = new BigInteger(g_value, g_radix);
		
		String p_value = properties.getProperty("P");
		int p_radix = Integer.parseInt(properties.getProperty("P-RADIX"));
		BigInteger p = new BigInteger(p_value, p_radix);
		
		int secret_key_size = Integer.parseInt(properties.getProperty("SECRET-KEY-SIZE"));
		
		String secret_key_algorithm = properties.getProperty("SECRET-KEY-ALGORITHM");
		String provider = properties.getProperty("DH-PROVIDER");
		
		String secure_random_algorithm = properties.getProperty("SECURE-RANDOM");
		SecureRandom sr = (secure_random_algorithm == null) ? SecureRandom.getInstance("sha1PRNG") : SecureRandom.getInstance(secure_random_algorithm);
		
		return new DiffieHellman(p, g, secret_key_size, secret_key_algorithm, provider, sr);
	}

}
