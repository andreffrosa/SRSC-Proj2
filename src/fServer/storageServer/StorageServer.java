package fServer.storageServer;

import java.security.KeyStore;

import fServer.authServer.TokenVerifier;
import rest.server.mySecureRestServer;
import ssl.CustomSSLServerSocketFactory;
import utility.MyKeyStore;
import utility.TLS_Utils;

public class StorageServer {

	public static void main(String[] args) throws Exception {
		if (args.length < 4) {
			System.err.println("Usage: AccessControlServer <port> <tls-configs> <keystore-configs> <token-verification>");
			System.exit(-1);
		}

		int port = Integer.parseInt(args[0]);
		String tls_configs = args[1];
		String keystores_configs = args[2];
		String token_verif = args[3];

		// Load KeyStores
		MyKeyStore[] ks_stores = TLS_Utils.loadKeyStores(keystores_configs);
		KeyStore ks = ks_stores[0].getKeystore();
		String ks_password = ks_stores[0].getPassword();
		KeyStore ts = ks_stores[1].getKeystore();

		TokenVerifier tokenVerifier = TokenVerifier.getVerifier(token_verif);

		// Create Service Handler
		StorageImplementation storage = new StorageImplementation(tokenVerifier);

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
