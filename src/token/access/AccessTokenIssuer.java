package token.access;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import token.AbstractTokenIssuer;
import utility.Cryptography;
import utility.IO;
import utility.MyKeyStore;

public class AccessTokenIssuer extends AbstractTokenIssuer {

	private MessageDigest hash_function;

	public AccessTokenIssuer(long token_ttl, KeyPair kp, Signature sig, MessageDigest hash_function) {
		super(token_ttl, kp, sig);
		this.hash_function = hash_function;
	}

	public MessageDigest getHash_function() {
		return hash_function;
	}

	public AccessToken newToken(String op_params, String op_type, long nonce) throws InvalidKeyException, SignatureException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		String data = op_params + op_type + nonce;
		
		byte[] hash = Cryptography.digest(hash_function, data.getBytes());

		long current_date = System.currentTimeMillis();
		long expiration_date = current_date + token_ttl;

		Map<String,String> public_attrs = new HashMap<>();
		public_attrs.put("Issued on", ""+current_date);

		return AccessToken.newToken(hash, expiration_date, public_attrs, sig, kp.getPrivate());
	}

	public static AccessTokenIssuer fromConfigFile(String config) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException {
		Properties properties = IO.loadProperties(config);

		long token_ttl = Long.parseLong(properties.getProperty("TOKEN-TTL"));
		String signature_algorithm = properties.getProperty("SIGNATURE-ALGORITHM");
		String signature_algorithm_provider = properties.getProperty("SIGNATURE-ALGORITHM-PROVIDER");

		String keystore_location = properties.getProperty("KEYSTORE-PATH");
		String keystore_type = properties.getProperty("KEYSTORE-TYPE");
		String keystore_password = properties.getProperty("KEYSTORE-PASSWORD");
		String certificate_alias = properties.getProperty("CERTIFICATE-ALIAS");
		
		String hash_algorithm = properties.getProperty("HASH-ALGORITHM");
		String hash_algorithm_provider = properties.getProperty("HASH-ALGORITHM-PROVIDER");

		MyKeyStore ks = new MyKeyStore(keystore_location, keystore_password, keystore_type);
		KeyStore.PrivateKeyEntry e = (PrivateKeyEntry) ks.getEntry(certificate_alias);

		KeyPair kp = new KeyPair(e.getCertificate().getPublicKey(), e.getPrivateKey());

		Signature sig = signature_algorithm_provider == null ? Signature.getInstance(signature_algorithm) : Signature.getInstance(signature_algorithm, signature_algorithm_provider);

		MessageDigest hash_function = null;
		if(hash_algorithm_provider != null)
			hash_function = MessageDigest.getInstance(hash_algorithm, hash_algorithm_provider);
		else
			hash_function = MessageDigest.getInstance(hash_algorithm);
		
		return new AccessTokenIssuer(token_ttl, kp, sig, hash_function);
	}

}
