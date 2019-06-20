package fServer.mainDispatcher;

import java.security.KeyStore;
import java.util.Properties;

import rest.server.mySecureRestServer;
import ssl.CustomSSLServerSocketFactory;
import token.TokenVerifier;
import utility.ArrayUtil;
import utility.IO;
import utility.MyKeyStore;
import utility.TLS_Utils;

public class MainDispatcherServer {

	public static void main(String[] args) throws Exception {

		if (args.length < 6) {
			System.err.println("Usage: MainDispatcher <port> <tls-configs> <keystore-configs> <service-endpoints> <auth-token-verification> <access-token-verification>");
			System.exit(-1);
		}

		int port = Integer.parseInt(args[0]);
		String tls_configs = args[1];
		String keystores_configs = args[2];
		String endpoints = args[3];
		String auth_token_verif = args[4];
		String access_token_verif = args[5];

		// Load KeyStores
		MyKeyStore[] ks_stores = TLS_Utils.loadKeyStores(keystores_configs);
		KeyStore ks = ks_stores[0].getKeystore();
		String ks_password = ks_stores[0].getPassword();
		KeyStore ts = ks_stores[1].getKeystore();

		// Read Endpoints
		Properties service_endpoints = IO.loadProperties(endpoints);
		String authentication_server = service_endpoints.getProperty("authentication-server");
		String access_control_server = service_endpoints.getProperty("access-control-server");
		String[] storage_servers = ArrayUtil.unparseString(service_endpoints.getProperty("storage-server"));

		TokenVerifier authTokenVerifier = TokenVerifier.getVerifier(auth_token_verif);
		TokenVerifier accessTokenVerifier = TokenVerifier.getVerifier(access_token_verif);

		// Create Service Handler
		RemoteFileService dispatcher = new MainDispatcherImplementation(authentication_server, access_control_server, storage_servers, authTokenVerifier, accessTokenVerifier, ks, ks_password, ts);

		// Create HTTPS Server
		CustomSSLServerSocketFactory factory =  TLS_Utils.buildServerSocketFactory(port, tls_configs, ks, ks_password, ts);
		mySecureRestServer server = new mySecureRestServer(port, dispatcher, factory);
		server.start();

		System.out.println("\n\t#######################################################"
					     + "\n\t   MainDispatcherServer ready @ " + server.getAddress()
					     + "\n\t                   TLS Version: " + factory.getTLSVersions()[0]
						 + "\n\t                  Chipersuites: " + factory.getDefaultCipherSuites()[0]
						 + "\n\t                  SecureRandom: " + (factory.getSecureRandom() == null ? "null" : factory.getSecureRandom().getAlgorithm())
						 + "\n\t         Client Authentication: " + factory.clientAuthentication() 
						 + "\n\t#######################################################");

	}

}
