package utility.tls;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;

public class myKeyStore {

	public static KeyStore load(String filename, String password, String type) throws Exception {
		try (InputStream ksIs = new FileInputStream(filename)) {
			KeyStore ks = KeyStore.getInstance(type);
			ks.load(ksIs, password.toCharArray());
			return ks;
		}
	}
}
