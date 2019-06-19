package fServer.storageServer.remote;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Properties;

import rest.server.mySecureRestServer;
import ssl.CustomSSLServerSocketFactory;
import token.TokenVerifier;
import utility.IO;
import utility.MyKeyStore;
import utility.TLS_Utils;

public class StorageServer {

	public static void main(String[] args) throws Exception {
		if (args.length < 6) {
			System.err.println("Usage: AccessControlServer <port> <tls-configs> <keystore-configs> <auth-token-verification> <access-token-verification> <dbPath>");
			System.exit(-1);
		}

		int port = Integer.parseInt(args[0]);
		String tls_configs = args[1];
		String keystores_configs = args[2];
		String auth_token_verif = args[3];
		String access_token_verif = args[4];
		String db_path = args[5];

		// Load KeyStores
		MyKeyStore[] ks_stores = TLS_Utils.loadKeyStores(keystores_configs);
		KeyStore ks = ks_stores[0].getKeystore();
		String ks_password = ks_stores[0].getPassword();
		KeyStore ts = ks_stores[1].getKeystore();

		Properties properties = IO.loadProperties(access_token_verif);
		String hash_algorithm = properties.getProperty("HASH-ALGORITHM");
		String hash_algorithm_provider = properties.getProperty("HASH-ALGORITHM-PROVIDER");
		MessageDigest hash_function = null;
		if(hash_algorithm_provider != null)
			hash_function = MessageDigest.getInstance(hash_algorithm, hash_algorithm_provider);
		else
			hash_function = MessageDigest.getInstance(hash_algorithm);
		
		// Create Service Handler
		TokenVerifier authTokenVerifier = TokenVerifier.getVerifier(auth_token_verif);
		TokenVerifier accessTokenVerifier = TokenVerifier.getVerifier(access_token_verif);
		StorageImplementation storage = new StorageImplementation(db_path, authTokenVerifier, accessTokenVerifier, hash_function);

		// Create HTTPS Server
		CustomSSLServerSocketFactory factory =  TLS_Utils.buildServerSocketFactory(port, tls_configs, ks, ks_password, ts);
		mySecureRestServer server = new mySecureRestServer(port, storage, factory);
		server.start();

		System.out.println("\n\t#######################################################"
					     + "\n\t         Storage Server ready @ " + server.getAddress()
					     + "\n\t                   TLS Version: " + factory.getTLSVersions()[0]
						 + "\n\t                  Chipersuites: " + factory.getDefaultCipherSuites()[0]
						 + "\n\t                  SecureRandom: " + (factory.getSecureRandom() == null ? "null" : factory.getSecureRandom().getAlgorithm())
						 + "\n\t         Client Authentication: " + factory.clientAuthentication() 
						 + "\n\t#######################################################");

	}

}
