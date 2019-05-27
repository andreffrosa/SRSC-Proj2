package fServer.authServer;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.AbstractMap;
import java.util.Map.Entry;
import java.util.Properties;

import utility.ArrayUtil;
import utility.IO;
import utility.MyKeyStore;

public class TokenIssuer {

	private long token_ttl;
	private KeyPair kp;
	private Signature sig;
	private String ciphersuite;
	private byte[] iv;
	
	public TokenIssuer(long token_ttl, KeyPair kp, Signature sig, String ciphersuite, byte[] iv) {
		this.token_ttl = token_ttl;
		this.kp = kp;
		this.sig = sig;
		this.ciphersuite = ciphersuite;
		this.iv = iv;
	}

	public String getCiphersuite() {
		return ciphersuite;
	}

	public byte[] getIv() {
		return iv;
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
	
	public AuthenticationToken newToken(User user) throws InvalidKeyException, SignatureException, IOException {
		String username = user.getUsername();
		long expiration_date = System.currentTimeMillis() + token_ttl;
		return AuthenticationToken.newToken(username, expiration_date, null, sig, kp.getPrivate());
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
		byte[] iv = ArrayUtil.unparse(properties.getProperty("IV"));
		
		MyKeyStore ks = new MyKeyStore(keystore_location, keystore_password, keystore_type);
		KeyStore.PrivateKeyEntry e = (PrivateKeyEntry) ks.getEntry(certificate_alias);
		
		KeyPair kp = new KeyPair(e.getCertificate().getPublicKey(), e.getPrivateKey());
		
		Signature sig = signature_algorithm_provider == null ? Signature.getInstance(signature_algorithm) : Signature.getInstance(signature_algorithm, signature_algorithm_provider);
		
		return new TokenIssuer(token_ttl, kp, sig, ciphersuite, iv);
	}
	
}
