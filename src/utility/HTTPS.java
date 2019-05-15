package utility;

import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ServerSocketFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.jdkhttp.JdkHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

@SuppressWarnings("restriction")
public class HTTPS {

	public static Client buildClient(KeyStore ks, String ks_password, String tls_version, String ciphersuites) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, KeyManagementException {

		ClientConfig config = new ClientConfig();
		//config.property(ClientProperties.CONNECT_TIMEOUT, CONNECT_TIMEOUT);
		//config.property(ClientProperties.READ_TIMEOUT, READ_TIMEOUT);

		SSLContext ctx = SSLContext.getInstance(tls_version);
		ctx.init(getKeyManager(ks, ks_password), null, null);

		/*final String[] supportedProtocols = useSystemProperties ? StringUtils.split(
	            System.getProperty("https.protocols")) : null;
	    final String[] supportedCipherSuites = useSystemProperties ? StringUtils.split(
	            System.getProperty("https.cipherSuites")) : null;
		 */

		/*LayeredConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext, supportedProtocols, supportedCipherSuites, hostnameVerifier);*/

		/*CloseableHttpClient httpClient = HttpClientBuilder
		          .create()
		          .setConnectionManager(myConnectionManager)
		          .setDefaultRequestConfig(rqConfig)
		          .setSSLSocketFactory(new SSLConnectionSocketFactory(
		                  SSLContexts.createSystemDefault(),
		                  new String[]{"TLSv1.2"},
		                  new String[] {"some-gibberish-cipher-suite"},
		                  SSLConnectionSocketFactory.getDefaultHostnameVerifier()))
		          .build();*/

		String[] cipherSuites = new String[] {ciphersuites};
		String[] protocols = new String[] {tls_version};
		
		SSLSocketFactory sslSocketFactory = new CustomSSLSocketFactory(ctx.getSocketFactory(), cipherSuites, protocols);

		HttpUrlConnectorProvider.ConnectionFactory factory = url -> {
			HttpsURLConnection httpsURLConnection = (HttpsURLConnection) url.openConnection();
			httpsURLConnection.setSSLSocketFactory(sslSocketFactory);

			return httpsURLConnection;
		};
		config.connectorProvider(new HttpUrlConnectorProvider().connectionFactory(factory));

		Client client = ClientBuilder.newBuilder()
				.hostnameVerifier((String hostname, SSLSession cts) -> true)
				.sslContext(ctx)
				.withConfig(config)
				.build();

		return client;
	}

	public static HttpsServer buildServer(Object handler, KeyStore ks, String ks_password, KeyStore ts, int port, String tls_version, boolean authenticate_clients, String ciphersuites, SecureRandom sr) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, KeyManagementException {

		// Set request handler
		ResourceConfig config = new ResourceConfig();
		config.register(handler);

		// Configure SSLContext
		SSLContext ctx = SSLContext.getInstance(tls_version);

		KeyManager[] km = getKeyManager(ks, ks_password);
		TrustManager[] tm = authenticate_clients ? getTrustManager(ts) : null;

		ctx.init(km, tm, sr);

		// Configure HTTPS Server
		HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());

		URI baseUri = UriBuilder.fromUri("https://0.0.0.0/").port(port).build();

		HttpsServer server = (HttpsServer) JdkHttpServerFactory.createHttpServer(baseUri, config, ctx, false);

		configureHTTPS(server, ctx, authenticate_clients, tls_version, ciphersuites);

		return server;
	}

	private static void configureHTTPS(HttpsServer server, SSLContext ctx, boolean authenticate_clients, String tls_version, String ciphersuites) {
		String[] cipherSuites = new String[] {ciphersuites};
		String[] protocols = new String[] {tls_version};

		server.setHttpsConfigurator(new HttpsConfigurator(ctx) {

			@Override
			public void configure(HttpsParameters params) {
				SSLParameters sslparams = ctx.getDefaultSSLParameters();
				sslparams.setNeedClientAuth(authenticate_clients);

				sslparams.setCipherSuites(cipherSuites);
				sslparams.setProtocols(protocols);

				params.setSSLParameters(sslparams);
			}
		});
	}

	private static KeyManager[] getKeyManager(KeyStore ks, String ks_password) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); // TODO: receber provider?
		//KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509"); // TODO: passar provider?
		kmf.init(ks, ks_password.toCharArray());

		return kmf.getKeyManagers();
	}

	private static TrustManager[] getTrustManager(KeyStore ts) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
		List<X509Certificate> trustedCertificates = new ArrayList<>();

		TrustManagerFactory tmf2 = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf2.init(ts);

		for (TrustManager tm : tmf2.getTrustManagers()) {
			if (tm instanceof X509TrustManager)
				trustedCertificates.addAll(Arrays.asList(((X509TrustManager) tm).getAcceptedIssuers()));
		}

		// Create a trust manager that does not validate certificate chains
		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {

			@Override
			public void checkClientTrusted(X509Certificate[] certs, String authType) {
				// System.err.println(certs[0].getSubjectX500Principal());
			}

			@Override
			public void checkServerTrusted(X509Certificate[] certs, String authType) {
				Thread.dumpStack();
			}

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return trustedCertificates.toArray(new X509Certificate[0]);
			}
		} };

		return trustAllCerts;
	}

}
