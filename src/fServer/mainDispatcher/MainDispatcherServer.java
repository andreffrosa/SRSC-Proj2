package fServer.mainDispatcher;

import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Properties;

import javax.net.ssl.SSLServerSocketFactory;

import fServer.authServer.TokenVerifier;
import rest.server.mySecureRestServer;
import ssl.CustomSSLServerSocketFactory;
import test.myHelloWorld;
import utility.IO;
import utility.MyKeyStore;

public class MainDispatcherServer {

	public static void main(String[] args) throws Exception {

		if (args.length < 5) {
			System.err.println("Usage: MainDispatcher <port> <tls-configs> <keystore-configs> <service-endpoints> <token-verification>");
			System.exit(-1);
		}

		int port = Integer.parseInt(args[0]);
		
		String token_verif = args[4];

		// Read Configs
		Properties tls_properties = IO.loadProperties(args[1]);
		
		String[] protocols = new String[] {tls_properties.getProperty("TLS-PROT-ENF")};
		boolean authenticate_clients = tls_properties.getProperty("TLS-AUTH").equals("MUTUAL");
		String[] ciphersuites = new String[] {tls_properties.getProperty("CIPHERSUITES")};
		String secure_random = tls_properties.getProperty("SECURE-RANDOM");
		SecureRandom sr = secure_random == null ? null : SecureRandom.getInstance(secure_random);
		
		// Read Keystore Properties
		Properties keystore_properties = IO.loadProperties(args[2]);
		
		// TODO: Transformar em constantes
		String keystore_path = keystore_properties.getProperty("keystore");
		String keystore_password = keystore_properties.getProperty("keystore-password");
		String keystore_type = keystore_properties.getProperty("keystore-type");
		String truststore_path = keystore_properties.getProperty("truststore");
		String truststore_password = keystore_properties.getProperty("truststore-password");
		String truststore_type = keystore_properties.getProperty("truststore-type");
		
		KeyStore ks = MyKeyStore.loadKeyStore(keystore_path, keystore_password, keystore_type);
		KeyStore ts = MyKeyStore.loadKeyStore(truststore_path, truststore_password, truststore_type);
		
		// Read Endpoints
		Properties service_endpoints = IO.loadProperties(args[3]);
		String authentication_server = service_endpoints.getProperty("authentication-server");
		String access_control_server = service_endpoints.getProperty("access-control-server");
		String storage_server = service_endpoints.getProperty("storage-server");
		
		TokenVerifier tokenVerifier = TokenVerifier.getVerifier(token_verif);

		// Create HTTPS Server
		RemoteFileService dispatcher = new MainDispatcherImplementation(authentication_server, access_control_server, storage_server, tokenVerifier, ks, keystore_password, ts);

		SSLServerSocketFactory factory =  new CustomSSLServerSocketFactory(ks, keystore_password, ts, ciphersuites, protocols, authenticate_clients, sr);
		mySecureRestServer server = new mySecureRestServer(port, dispatcher, factory);
		server.start();
		
		System.out.println("\n\t#######################################################"
				         + "\n\t      MainDispatcher ready @ " + server.getAddress()
				         + "\n\t                TLS Version: " + protocols[0]
				         + "\n\t               Chipersuites: " + ciphersuites[0]
				         + "\n\t               SecureRandom: " + secure_random
				         + "\n\t      Client Authentication: " + authenticate_clients 
			             + "\n\t#######################################################");

	}

}
