package fServer.authServer;

import java.io.IOException;
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
import java.util.Properties;

import utility.IO;
import utility.MyKeyStore;

public class TokenIssuer {

	private long token_ttl;
	private KeyPair kp;
	private Signature sig;
	private String ciphersuite;
	private boolean use_iv;
	private int iv_size;
	
	public TokenIssuer(long token_ttl, KeyPair kp, Signature sig, String ciphersuite, boolean use_iv, int iv_size) {
		this.token_ttl = token_ttl;
		this.kp = kp;
		this.sig = sig;
		this.ciphersuite = ciphersuite;
		this.use_iv = use_iv;
		this.iv_size = iv_size;
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
		boolean use_iv = Boolean.parseBoolean(properties.getProperty("USE-IV", "false"));
		int iv_size = Integer.parseInt(properties.getProperty("IV-SIZE", "0"));
		
		MyKeyStore ks = new MyKeyStore(keystore_location, keystore_password, keystore_type);
		KeyStore.PrivateKeyEntry e = (PrivateKeyEntry) ks.getEntry(certificate_alias);
		
		KeyPair kp = new KeyPair(e.getCertificate().getPublicKey(), e.getPrivateKey());
		
		Signature sig = signature_algorithm_provider == null ? Signature.getInstance(signature_algorithm) : Signature.getInstance(signature_algorithm, signature_algorithm_provider);
		
		return new TokenIssuer(token_ttl, kp, sig, ciphersuite, use_iv, iv_size);
	}
	
	
}
