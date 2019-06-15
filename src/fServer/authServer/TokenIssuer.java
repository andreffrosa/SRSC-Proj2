package fServer.authServer;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import utility.Cryptography;
import utility.IO;
import utility.MyKeyStore;

public class TokenIssuer {

	private long token_ttl;
	private KeyPair kp;
	private Signature sig;
	private String ciphersuite;
	private String provider;
	private boolean use_iv;
	private int iv_size;

	public TokenIssuer(long token_ttl, KeyPair kp, Signature sig, String ciphersuite, String provider, boolean use_iv, int iv_size) {
		this.token_ttl = token_ttl;
		this.kp = kp;
		this.sig = sig;
		this.ciphersuite = ciphersuite;
		this.use_iv = use_iv;
		this.iv_size = iv_size;
	}

	public String getProvider() {
		return provider;
	}

	public String getCiphersuite() {
		return ciphersuite;
	}

	public long getToken_ttl() {
		return token_ttl;
	}

	public KeyPair getKp() {
		return kp;
	}

	public Signature getSig() {
		return sig;
	}	

	public boolean useIv() {
		return use_iv;
	}

	public int getIv_size() {
		return iv_size;
	}

	public Entry<AuthenticationToken, byte[]> newToken(User user, SecretKey ks) throws InvalidKeyException, SignatureException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		String username = user.getUsername();

		long current_date = System.currentTimeMillis();
		long expiration_date = current_date + token_ttl;

		Map<String,String> public_attrs = new HashMap<>();
		public_attrs.put("Issued on", ""+current_date);

		Map<String,String> private_attrs = new HashMap<>();
		private_attrs.put("name", user.getName());

		// Generate new IV
		byte[] iv = null;
		if(this.useIv()) {
			iv = Cryptography.createIV(this.getIv_size());
		} else {
			iv = new byte[0];
		}

		Cipher encryptionCipher = Cryptography.buildCipher(ciphersuite, Cipher.ENCRYPT_MODE, ks, iv, provider);

		AuthenticationToken token = AuthenticationToken.newToken(username, expiration_date, public_attrs, private_attrs, sig, kp.getPrivate(), encryptionCipher);

		return new AbstractMap.SimpleEntry<AuthenticationToken, byte[]>(token, iv);
	}

	public static TokenIssuer fromConfigFile(String config) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException {
		Properties properties = IO.loadProperties(config);

		long token_ttl = Long.parseLong(properties.getProperty("TOKEN-TTL"));
		String signature_algorithm = properties.getProperty("SIGNATURE-ALGORITHM");
		String signature_algorithm_provider = properties.getProperty("SIGNATURE-ALGORITHM-PROVIDER");

		String keystore_location = properties.getProperty("KEYSTORE-PATH");
		String keystore_type = properties.getProperty("KEYSTORE-TYPE");
		String keystore_password = properties.getProperty("KEYSTORE-PASSWORD");
		String certificate_alias  = properties.getProperty("CERTIFICATE-ALIAS");

		String ciphersuite = properties.getProperty("CIPHERSUITE");
		String provider = properties.getProperty("PROVIDER");

		boolean use_iv = Boolean.parseBoolean(properties.getProperty("USE-IV", "false"));
		int iv_size = Integer.parseInt(properties.getProperty("IV-SIZE", "0"));

		MyKeyStore ks = new MyKeyStore(keystore_location, keystore_password, keystore_type);
		KeyStore.PrivateKeyEntry e = (PrivateKeyEntry) ks.getEntry(certificate_alias);

		KeyPair kp = new KeyPair(e.getCertificate().getPublicKey(), e.getPrivateKey());

		Signature sig = signature_algorithm_provider == null ? Signature.getInstance(signature_algorithm) : Signature.getInstance(signature_algorithm, signature_algorithm_provider);

		return new TokenIssuer(token_ttl, kp, sig, ciphersuite, provider, use_iv, iv_size);
	}

}
