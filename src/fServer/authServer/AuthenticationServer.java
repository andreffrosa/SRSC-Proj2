package fServer.authServer;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Map;
import java.util.Properties;

import rest.server.mySecureRestServer;
import ssl.CustomSSLServerSocketFactory;
import utility.IO;
import utility.LoginUtility;
import utility.MyKeyStore;
import utility.TLS_Utils;

public class AuthenticationServer {
	
	private static DiffieHellman dh;
	private static TokenIssuer tokenIssuer;
	private static LoginUtility login_util;

	public static void main(String[] args) throws Exception {
		
		if (args.length < 5) {
			System.err.println("Usage: AuthenticationServer <port> <tls-configs> <keystore-configs> <authentication-table> <login-config>");
			System.exit(-1);
		}

		int port = Integer.parseInt(args[0]);
		String tls_configs = args[1];
		String keystores_configs = args[2];
		String auth_table = args[3];
		String login_config = args[4];
		
		// Load KeyStores
		MyKeyStore[] ks_stores = TLS_Utils.loadKeyStores(keystores_configs);
		KeyStore ks = ks_stores[0].getKeystore();
		String ks_password = ks_stores[0].getPassword();
		KeyStore ts = ks_stores[1].getKeystore();
		
		// Create Service handler
		loadLoginConfigs(login_config);
		Map<String,User> authentication_table = User.parseAuthenticationTable(auth_table);
		AuthenticatorService auth = new AuthenticatorServiceImpl(dh, authentication_table, tokenIssuer, login_util);

		// Create HTTPS Server
		CustomSSLServerSocketFactory factory =  TLS_Utils.buildServerSocketFactory(port, tls_configs, ks, ks_password, ts);
		mySecureRestServer server = new mySecureRestServer(port, auth, factory);
		server.start();

		System.out.println("\n\t#######################################################"
					     + "\n\t   AuthenticationServer ready @ " + server.getAddress()
					     + "\n\t                   TLS Version: " + factory.getTLSVersions()[0]
						 + "\n\t                  Chipersuites: " + factory.getDefaultCipherSuites()[0]
						 + "\n\t                  SecureRandom: " + (factory.getSecureRandom() == null ? "null" : factory.getSecureRandom().getAlgorithm())
						 + "\n\t         Client Authentication: " + factory.clientAuthentication() 
						 + "\n\t#######################################################");
	}
	
	private static void loadLoginConfigs(String path) throws Exception {
		Properties properties = IO.loadProperties(path);
		
		String g_value = properties.getProperty("G");
		int g_radix = Integer.parseInt(properties.getProperty("G-RADIX"));
		BigInteger g = new BigInteger(g_value, g_radix);
		
		String p_value = properties.getProperty("P");
		int p_radix = Integer.parseInt(properties.getProperty("P-RADIX"));
		BigInteger p = new BigInteger(p_value, p_radix);
		
		int secret_key_size = Integer.parseInt(properties.getProperty("SECRET-KEY-SIZE"));
		
		String secret_key_algorithm = properties.getProperty("SECRET-KEY-ALGORITHM");
		String secret_key_provider = properties.getProperty("SECRET-KEY-ALGORITHM-PROVIDER");
		
		String secure_random_algorithm = properties.getProperty("SECURE-RANDOM");
		SecureRandom sr = (secure_random_algorithm == null) ? SecureRandom.getInstance("sha1PRNG") : SecureRandom.getInstance(secure_random_algorithm);
		
		dh = new DiffieHellman(p, g, secret_key_size, secret_key_algorithm, secret_key_provider, sr);
		
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
		
		tokenIssuer = new TokenIssuer(token_ttl, kp, sig, ciphersuite, provider, use_iv, iv_size);
		
		String hash_algorithm = properties.getProperty("HASH-ALGORITHM");
		String hash_algorithm_provider = properties.getProperty("HASH-ALGORITHM-PROVIDER");
		
		String pbe_algorithm = properties.getProperty("PBE-ALGORITHM");
		String pbe_algorithm_provider = properties.getProperty("PBE-ALGORITHM-PROVIDER");
		int iterations = Integer.parseInt(properties.getProperty("ITERATIONS"));
		
		login_util =  new LoginUtility(hash_algorithm, hash_algorithm_provider, pbe_algorithm, pbe_algorithm_provider, iterations);
	}

}
