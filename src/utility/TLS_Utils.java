package utility;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;

import ssl.CustomSSLServerSocketFactory;

public class TLS_Utils {
	
	private static final String SECURE_RANDOM = "SECURE-RANDOM";
	private static final String CIPHERSUITES = "CIPHERSUITES";
	private static final String TLS_AUTH_MUTUAL = "MUTUAL";
	private static final String TLS_AUTH = "TLS-AUTH";
	private static final String TLS_PROT_ENF = "TLS-PROT-ENF";
	private static final String TRUSTSTORE_TYPE = "truststore-type";
	private static final String TRUSTSTORE_PASSWORD = "truststore-password";
	private static final String TRUSTSTORE = "truststore";
	private static final String KEYSTORE_TYPE = "keystore-type";
	private static final String KEYSTORE_PASSWORD = "keystore-password";
	private static final String KEYSTORE = "keystore";

	public static CustomSSLServerSocketFactory buildServerSocketFactory(int port, String tls_configs, KeyStore ks, String ks_password, KeyStore ts) throws IOException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
		Properties tls_properties = IO.loadProperties(tls_configs);

		String[] protocols = new String[] {tls_properties.getProperty(TLS_PROT_ENF)};
		boolean authenticate_clients = tls_properties.getProperty(TLS_AUTH).equals(TLS_AUTH_MUTUAL);
		String[] ciphersuites = new String[] {tls_properties.getProperty(CIPHERSUITES)};
		String secure_random = tls_properties.getProperty(SECURE_RANDOM);
		SecureRandom sr = secure_random == null ? null : SecureRandom.getInstance(secure_random);
		
		return new CustomSSLServerSocketFactory(ks, ks_password, ts, ciphersuites, protocols, authenticate_clients, sr);
	}
	
	public static MyKeyStore[] loadKeyStores(String keystores_config) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		Properties keystore_properties = IO.loadProperties(keystores_config);

		String keystore_path = keystore_properties.getProperty(KEYSTORE);
		String keystore_password = keystore_properties.getProperty(KEYSTORE_PASSWORD);
		String keystore_type = keystore_properties.getProperty(KEYSTORE_TYPE);
		String truststore_path = keystore_properties.getProperty(TRUSTSTORE);
		String truststore_password = keystore_properties.getProperty(TRUSTSTORE_PASSWORD);
		String truststore_type = keystore_properties.getProperty(TRUSTSTORE_TYPE);
		
		MyKeyStore ks = new MyKeyStore(keystore_path, keystore_password, keystore_type);
		MyKeyStore ts = new MyKeyStore(truststore_path, truststore_password, truststore_type);
		
		return new MyKeyStore[] {ks, ts};
	}

}
