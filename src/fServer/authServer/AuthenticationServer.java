package fServer.authServer;

import java.security.KeyStore;
import java.util.Map;

import rest.server.mySecureRestServer;
import ssl.CustomSSLServerSocketFactory;
import token.auth.AuthTokenIssuer;
import utility.LoginUtility;
import utility.MyKeyStore;
import utility.TLS_Utils;

public class AuthenticationServer {

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
		DiffieHellman dh = DiffieHellman.buildDH(login_config);
		AuthTokenIssuer tokenIssuer = AuthTokenIssuer.fromConfigFile(login_config);
		LoginUtility login_util = LoginUtility.fromConfig(login_config);
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

}
