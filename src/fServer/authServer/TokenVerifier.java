package fServer.authServer;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.AbstractMap;
import java.util.Properties;
import java.util.Map.Entry;

import utility.IO;
import utility.MyKeyStore;

public class TokenVerifier {

	private PublicKey tokenIssuerPubKey;
	private Signature sig;
	
	public TokenVerifier(PublicKey tokenIssuerPubKey, Signature sig) {
		this.tokenIssuerPubKey = tokenIssuerPubKey;
		this.sig = sig;
	}

	public PublicKey getTokenIssuerPubKey() {
		return tokenIssuerPubKey;
	}

	public Signature getSig() {
		return sig;
	}
	
	public boolean validateToken(long current_time, AuthenticationToken token) throws InvalidKeyException, SignatureException {
		return token.isValid(current_time, sig, tokenIssuerPubKey);
	}
	
	public static TokenVerifier getVerifier(String config) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException {
		Properties properties = IO.loadProperties(config);
		
		String signature_algorithm = properties.getProperty("SIGNATURE-ALGORITHM");
		String signature_algorithm_provider = properties.getProperty("SIGNATURE-ALGORITHM-PROVIDER");
		
		String truststore_location = properties.getProperty("TRUSTSTORE-PATH");
		String truststore_type = properties.getProperty("TRUSTSTORE-TYPE");
		String truststore_password = properties.getProperty("TRUSTSTORE-PASSWORD");
		String certificate_alias  = properties.getProperty("CERTIFICATE-ALIAS");
		
		MyKeyStore ts = new MyKeyStore(truststore_location, truststore_password, truststore_type);
		KeyStore.TrustedCertificateEntry e = (KeyStore.TrustedCertificateEntry) ts.getEntry(certificate_alias);
		
		PublicKey pubKey = e.getTrustedCertificate().getPublicKey();
		
		Signature sig = signature_algorithm_provider == null ? Signature.getInstance(signature_algorithm) : Signature.getInstance(signature_algorithm, signature_algorithm_provider);
		
		return new TokenVerifier(pubKey, sig);
	}
}
