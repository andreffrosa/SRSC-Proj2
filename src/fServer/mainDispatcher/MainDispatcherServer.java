package fServer.mainDispatcher;

import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Properties;

import com.sun.net.httpserver.HttpsServer;

import utility.HTTPS;
import utility.IO;
import utility.MyKeyStore;

@SuppressWarnings("restriction")
public class MainDispatcherServer {

	public static void main(String[] args) throws Exception {

		if (args.length < 3) {
			System.err.println("Usage: MainDispatcher <port> <tls-configs> <keystore-configs> <service-endpoints>");
			System.exit(-1);
		}

		int port = Integer.parseInt(args[0]);

		// Read Configs
		Properties tls_properties = IO.loadProperties(args[1]);
		
		String tls_version = tls_properties.getProperty("TLS-PROT-ENF");
		boolean authenticate_clients = tls_properties.getProperty("TLS-AUTH").equals("MUTUAL");
		String ciphersuites = tls_properties.getProperty("CIPHERSUITES");
		
		SecureRandom sr = null; // TODO: obter do ficheiro
		
		// Read Keystore Properties
		Properties keystore_properties = IO.loadProperties(args[2]);
		
		// TODO: Transformar em constantes
		String keystore_path = keystore_properties.getProperty("keystore");
		String keystore_password = keystore_properties.getProperty("keystore-password");
		String keystore_type = keystore_properties.getProperty("keystore-type");
		String truststore_path = keystore_properties.getProperty("truststore");
		String truststore_password = keystore_properties.getProperty("truststore-password");
		String truststore_type = keystore_properties.getProperty("truststore-type");
		
		System.setProperty("java.net.preferIPv4Stack", "true"); // Aqui ou nas runconfigs?
	
		// Acho que já não é preciso isto
		/*System.setProperty("javax.net.ssl.keyStore", server_keystore);
		System.setProperty("javax.net.ssl.keyStorePassword", keystore_password);
		System.setProperty("javax.net.ssl.trustStore", server_truststore);
		System.setProperty("javax.net.ssl.trustStorePassword", truststore_password);*/
		
		KeyStore ks = MyKeyStore.loadKeyStore(keystore_path, keystore_password, keystore_type);
		KeyStore ts = MyKeyStore.loadKeyStore(truststore_path, truststore_password, truststore_type);
		
		// Read Endpoints
		Properties service_endpoints = IO.loadProperties(args[3]);
		
		// TODO: read the loation of the other services
		
		
		//

		MainDispatcher dispatcher = new MainDispatcherImplementation();

		// Passar o endereço 0.0.0.0 também?
		HttpsServer server = HTTPS.buildServer(dispatcher, ks, keystore_password, ts, port, tls_version, authenticate_clients, ciphersuites, sr);
		
		server.start();

		System.out.println("\n\t#######################################################"
				         + "\n\t      MainDispatcher ready @ " + "https:/" + server.getAddress() 
				         + "\n\t      TLS Version: " + tls_version
				         + "\n\t      Client Authentication: " + authenticate_clients 
			             + "\n\t#######################################################");

	}

}
