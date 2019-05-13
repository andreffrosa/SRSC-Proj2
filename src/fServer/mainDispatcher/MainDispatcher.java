package fServer.mainDispatcher;

import java.net.URI;

import javax.net.ssl.SSLContext;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.server.ResourceConfig;
import java.net.URI;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.jdkhttp.JdkHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import com.sun.net.httpserver.HttpsServer;

import utility.tls.ClientCertificateVerifier;

@SuppressWarnings("restriction")
public class MainDispatcher {

	// Constants -> TODO: receber de um ficheiro de configs
	private static final String PATH = "./configs/fServer/mainDispatcher/";
	private static final String SERVER_KEYSTORE = PATH + "mainDispatcher-keystore.pkcs12";
	private static final String SERVER_KEYSTORE_PWD = "SRSC1819";
	private static final String SERVER_TRUSTSTORE = PATH + "mainDispatcher-truststore.pkcs12";
	private static final String SERVER_TRUSTSTORE_PWD = "SRSC1819";

	public static void main(String[] args) throws Exception {

		System.setProperty("java.net.preferIPv4Stack", "true");
		System.setProperty("javax.net.ssl.keyStore", SERVER_KEYSTORE);
		System.setProperty("javax.net.ssl.keyStorePassword", SERVER_KEYSTORE_PWD);
		System.setProperty("javax.net.ssl.trustStore", SERVER_TRUSTSTORE);
		System.setProperty("javax.net.ssl.trustStorePassword", SERVER_TRUSTSTORE_PWD);

		if (args.length < 3) {
			System.err.println("Usage: MainDispatcher <port> <configs-path> <service-endpoints>");
			System.exit(-1);
		}

		int port = Integer.parseInt(args[0]);

		// Read Configs
		
		// Read Endpoints
		
		boolean authenticate_clients = false;

		//DistributedWallet wallet = new BFTReplicatedWallet(id, byzantine);

		URI baseUri = UriBuilder.fromUri("https://0.0.0.0/").port(port).build();

		HttpsServer server = null;
		SSLContext ctx = null;

		ResourceConfig config = new ResourceConfig();
		config.register(wallet);

		if (authenticate_clients) {
			ClientCertificateVerifier ccv = new ClientCertificateVerifier();
			ctx = ccv.init(SERVER_KEYSTORE, SERVER_KEYSTORE_PWD, "PKCS12", SERVER_TRUSTSTORE, SERVER_TRUSTSTORE_PWD, "PKCS12", "TLSv1.2");

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
