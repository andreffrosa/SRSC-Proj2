package fServer.mainDispatcher;

import java.net.URI;
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.jdkhttp.JdkHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import com.sun.net.httpserver.HttpsServer;

import utility.IO;
import utility.tls.ClientCertificateVerifier;

@SuppressWarnings("restriction")
public class MainDispatcher {

	public static void main(String[] args) throws Exception {

		if (args.length < 3) {
			System.err.println("Usage: MainDispatcher <port> <tls-configs> <keystore-configs> <service-endpoints>");
			System.exit(-1);
		}

		int port = Integer.parseInt(args[0]);

		// Read Configs
		Properties tls_properties = IO.loadProperties(args[1]);
		
		// TODO: ler as configs tls 
		
		// Read Keystore Properties
		Properties keystore_properties = IO.loadProperties(args[2]);
		
		// TODO: Transformar em constantes
		String server_keystore = keystore_properties.getProperty("keystore");
		String keystore_password = keystore_properties.getProperty("keystore-password");
		String keystore_type = keystore_properties.getProperty("keystore-type");
		String server_truststore = keystore_properties.getProperty("truststore");
		String truststore_password = keystore_properties.getProperty("truststore-password");
		String truststore_type = keystore_properties.getProperty("truststore-type");
		
		System.setProperty("java.net.preferIPv4Stack", "true");
		System.setProperty("javax.net.ssl.keyStore", server_keystore);
		System.setProperty("javax.net.ssl.keyStorePassword", keystore_password);
		System.setProperty("javax.net.ssl.trustStore", server_truststore);
		System.setProperty("javax.net.ssl.trustStorePassword", truststore_password);
		
		// Read Endpoints
		Properties service_endpoints = IO.loadProperties(args[3]);
		
		// TODO: read the loation of the other services
		
		
		//
		
		boolean authenticate_clients = false;

		//DistributedWallet wallet = new BFTReplicatedWallet(id, byzantine);

		URI baseUri = UriBuilder.fromUri("https://0.0.0.0/").port(port).build();

		HttpsServer server = null;
		SSLContext ctx = null;

		ResourceConfig config = new ResourceConfig();
		config.register(wallet);

		if (authenticate_clients) {
			ClientCertificateVerifier ccv = new ClientCertificateVerifier();
			ctx = ccv.init(server_keystore, keystore_password, keystore_password, server_truststore, truststore_password, truststore_type, "TLSv1.2");

			HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());

			server = (HttpsServer) JdkHttpServerFactory.createHttpServer(baseUri, config, ctx, false);

			ccv.configureHttps(server);
		} else {
			ctx = SSLContext.getDefault();

			server = (HttpsServer) JdkHttpServerFactory.createHttpServer(baseUri, config, ctx, false);
		}

		server.start();

		System.out.println("\n\t#######################################################"
				         + "\n\t      MainDispatcher ready @ " + baseUri 
				         + "\n\t      Client Authentication: " + authenticate_clients 
			             + "\n\t#######################################################");

	}

}
