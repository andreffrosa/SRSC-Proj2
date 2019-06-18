package fServer.storageServer.dropbox;

import java.awt.Desktop;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.URI;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;

import org.glassfish.jersey.jdkhttp.JdkHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;
import org.pac4j.scribe.builder.api.DropboxApi20;

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;

import utility.JSON;

public class DropboxClient {
	private static final String apiKey = "8pyl8ao463ljg3h";
	private static final String apiSecret = "tv05dt8uu38kvyp";

	protected static final String JSON_CONTENT_TYPE = "application/json; charset=utf-8";
	protected static final String OCTET_STREAM_CONTENT_TYPE = "application/octet-stream";

	protected OAuth20Service service;
	protected OAuth2AccessToken accessToken;

	private static final String TOKEN_FILE = "/home/srsc/tokenFile";

	protected DropboxClient() {
		try {

			OAuthCallbackServlet.start(this);

			service = new ServiceBuilder()
					.apiKey(apiKey)
					.apiSecret(apiSecret)
					.callback(OAuthCallbackServlet.CALLBACK_URI)
					.build(DropboxApi20.INSTANCE);

			FileInputStream fis = new FileInputStream(TOKEN_FILE);
			byte[] b = new byte[1024];
			int n = fis.read(b);
			fis.close();
			String token = new String(b, 0, n);

			accessToken = JSON.decode(token, OAuth2AccessToken.class);

			if (accessToken == null) {
				String authorizationURL = service.getAuthorizationUrl();
				System.out.println("Open the following URL in a browser:\n" + authorizationURL);

				Desktop.getDesktop().browse(new URI(authorizationURL));

				while (accessToken == null) {
					try {
						Thread.sleep(100);
					} catch (Exception a) {
					}
				}
				System.out.println("Got access token!");
			}

		} catch (Exception x) {
			x.printStackTrace();
		}
	}

	protected synchronized void setToken(String code) {
		System.out.println("Code: " + code);
		try {
			accessToken = service.getAccessToken(code);

			// Write to file
			FileOutputStream fos = new FileOutputStream(TOKEN_FILE);
			fos.write(JSON.encode(accessToken).getBytes());
			fos.flush();
			fos.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Path("/")
	public static class OAuthCallbackServlet {
		public static final String CALLBACK_URI = "http://localhost:5555/";

		static DropboxClient client;

		@GET
		public String callback(@QueryParam("code") String code) {

			System.out.println("Got token: " + code);

			client.setToken(code);

			return String.format("<html>Authorization-Code: %s</html>", code);
		}

		public static void start(DropboxClient d) {
			client = d;
			ResourceConfig config = new ResourceConfig();
			config.register(new OAuthCallbackServlet());
			JdkHttpServerFactory.createHttpServer(URI.create(CALLBACK_URI), config);
			System.out.println("Running callback...");
		}
	}
}