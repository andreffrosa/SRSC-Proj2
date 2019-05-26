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

	public static CustomSSLServerSocketFactory buildServerSocketFactory(int port, String tls_configs, KeyStore ks, String ks_password, KeyStore ts) throws IOException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
		Properties tls_properties = IO.loadProperties(tls_configs);

		String[] protocols = new String[] {tls_properties.getProperty("TLS-PROT-ENF")};
		boolean authenticate_clients = tls_properties.getProperty("TLS-AUTH").equals("MUTUAL");
		String[] ciphersuites = new String[] {tls_properties.getProperty("CIPHERSUITES")};
		String secure_random = tls_properties.getProperty("SECURE-RANDOM");
		SecureRandom sr = secure_random == null ? null : SecureRandom.getInstance(secure_random);
		
		return new CustomSSLServerSocketFactory(ks, ks_password, ts, ciphersuites, protocols, authenticate_clients, sr);
	}
	
	public static MyKeyStore[] loadKeyStores(String keystores_config) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		Properties keystore_properties = IO.loadProperties(keystores_config);

		String keystore_path = keystore_properties.getProperty("keystore");
		String keystore_password = keystore_properties.getProperty("keystore-password");
		String keystore_type = keystore_properties.getProperty("keystore-type");
		String truststore_path = keystore_properties.getProperty("truststore");
		String truststore_password = keystore_properties.getProperty("truststore-password");
		String truststore_type = keystore_properties.getProperty("truststore-type");
		
		MyKeyStore ks = new MyKeyStore(keystore_path, keystore_password, keystore_type);
		MyKeyStore ts = new MyKeyStore(truststore_path, truststore_password, truststore_type);
		
		return new MyKeyStore[] {ks, ts};
	}

}
