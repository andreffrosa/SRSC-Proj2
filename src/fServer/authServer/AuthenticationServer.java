package fServer.authServer;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Properties;

import rest.server.mySecureRestServer;
import ssl.CustomSSLServerSocketFactory;
import utility.DiffieHellman;
import utility.IO;
import utility.MyKeyStore;
import utility.TLS_Utils;

public class AuthenticationServer {

	public static void main(String[] args) throws Exception {
		if (args.length < 6) {
			System.err.println("Usage: AuthenticationServer <port> <tls-configs> <keystore-configs> <authentication-table> <dh-config-file> <token-config>");
			System.exit(-1);
		}

		int port = Integer.parseInt(args[0]);
		String tls_configs = args[1];
		String keystores_configs = args[2];
		String auth_table = args[3];
		String dh_config = args[4];
		String token_config = args[5];
		
		System.setProperty("java.net.preferIPv4Stack", "true"); // Aqui ou nas runconfigs?

		// Load KeyStores
		MyKeyStore[] ks_stores = TLS_Utils.loadKeyStores(keystores_configs);
		KeyStore ks = ks_stores[0].getKeystore();
		String ks_password = ks_stores[0].getPassword();
		KeyStore ts = ks_stores[1].getKeystore();
		
		// Create Service handler
		DiffieHellman dh = buildDH(dh_config);
		Map<String,User> authentication_table = User.parseAuthenticationTable(auth_table);
		TokenIssuer tokenIssuer = TokenIssuer.fromConfigFile(token_config);
		AuthenticatorService auth = new AuthenticatorServiceImpl(dh, authentication_table, tokenIssuer);

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
	
	private static DiffieHellman buildDH(String dh_config_file) throws NoSuchAlgorithmException, IOException {
		Properties properties = IO.loadProperties(dh_config_file);
		
		String g_value = properties.getProperty("G");
		int g_radix = Integer.parseInt(properties.getProperty("G-RADIX"));
		BigInteger g = new BigInteger(g_value, g_radix);
		
		String p_value = properties.getProperty("P");
		int p_radix = Integer.parseInt(properties.getProperty("P-RADIX"));
		BigInteger p = new BigInteger(p_value, p_radix);
		
		int secret_key_size = Integer.parseInt(properties.getProperty("SECRET-KEY-SIZE"));
		
		String secret_key_algorithm = properties.getProperty("SECRET-KEY-ALGORITHM");
		String provider = properties.getProperty("PROVIDER");
		
		String secure_random_algorithm = properties.getProperty("SECURE-RANDOM");
		SecureRandom sr = (secure_random_algorithm == null) ? SecureRandom.getInstance("sha1PRNG") : SecureRandom.getInstance(secure_random_algorithm);
		
		return new DiffieHellman(p, g, secret_key_size, secret_key_algorithm, provider, sr);
	}

}
