import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Properties;

import client.RemoteFileServiceClient;
import fileService.RemoteFileService;
import utility.ArrayUtil;
import utility.IO;
import utility.MyKeyStore;

public class Test {

	public static void main(String[] args) throws Exception {

		// Read Keystore Properties
		Properties keystore_properties = IO.loadProperties("./configs/client/keystores.conf");

		// TODO: Transformar em constantes
		String keystore_path = keystore_properties.getProperty("keystore");
		String keystore_password = keystore_properties.getProperty("keystore-password");
		String keystore_type = keystore_properties.getProperty("keystore-type");
		String truststore_path = keystore_properties.getProperty("truststore");
		String truststore_password = keystore_properties.getProperty("truststore-password");
		String truststore_type = keystore_properties.getProperty("truststore-type");

		System.setProperty("java.net.preferIPv4Stack", "true"); // Aqui ou nas runconfigs?

		KeyStore ks = MyKeyStore.loadKeyStore(keystore_path, keystore_password, keystore_type);
		KeyStore ts = MyKeyStore.loadKeyStore(truststore_path, truststore_password, truststore_type);
		
		String location = "https://localhost:8888/";
		
		byte[] iv = ArrayUtil.unparse(IO.loadProperties("./configs/client/login.conf").getProperty("IV"));
		
		RemoteFileServiceClient client = new RemoteFileServiceClient(ks, keystore_password, ts, location, iv);
		
		client.login("fifo", "xé");
	}

}
