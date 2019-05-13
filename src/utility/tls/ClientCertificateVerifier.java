package utility.tls;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

@SuppressWarnings("restriction")
public class ClientCertificateVerifier {

	private SSLContext ctx;

	public SSLContext init(String server_ks, String server_ks_pwd, String ks_type, String server_ts, String server_ts_pwd, String ts_type, String tls_version) {

		List<X509Certificate> trustedCertificates = new ArrayList<>();

		try (InputStream ksIs = new FileInputStream(server_ks)) {

			KeyStore ks = myKeyStore.load(server_ks, server_ks_pwd, ks_type);
			KeyStore ts = myKeyStore.load(server_ts, server_ts_pwd, ts_type);

			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(ks, server_ks_pwd.toCharArray());

			ctx = SSLContext.getInstance(tls_version);

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

			ctx.init(kmf.getKeyManagers(), trustAllCerts, null);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return ctx;
	}

	public void configureHttps(HttpsServer server) {

		server.setHttpsConfigurator(new HttpsConfigurator(ctx) {
			@Override
			public void configure(HttpsParameters params) {
				SSLParameters sslparams = ctx.getDefaultSSLParameters();
				sslparams.setNeedClientAuth(true);
				params.setSSLParameters(sslparams);
			}
		});
	}

	public SSLContext getSSLContext() {
		return ctx;
	}

}
