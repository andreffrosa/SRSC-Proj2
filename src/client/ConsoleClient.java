package client;

import java.io.Console;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;
import java.util.Scanner;

import utility.IO;
import utility.MyKeyStore;


public class ConsoleClient {

	//Operations
	private static final String LOGIN = "login";
	private static final String LIST_FILES = "ls";
	private static final String NEW_DIRECTORY = "mkdir";
	private static final String UPLOAD = "put";
	private static final String DOWNLOAD = "get";
	private static final String COPY = "cp";
	private static final String REMOVE_FILE = "rm";
	private static final String REMOVE_DIR = "rmdir";
	private static final String FILE_METADATA = "file";


	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, KeyManagementException {

		Scanner in = new Scanner(System.in);

		// Receive from args the location of the configuration files
		//TODO

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

		RemoteFileServiceClient client = new RemoteFileServiceClient(ks, keystore_password, ts, location);

		String current_path = "";
		boolean logedIn = false;

		// Process user commands
		String cmd;
		boolean exit = false;
		while(!exit) {
			System.out.print("$" + current_path + "> ");
			cmd = in.next();

			if(!logedIn) {
				switch(cmd) {
				case "login":
					String username = login(in, client);
					if(username != null) {
						current_path = "/" + username + "/";
						logedIn = true;
					}
					break;
				case "exit":
					exit = true;
					break;
				default:
					System.out.println("Unsupported operation!");
					// TODO: Apresnetar lista de comandos disponiveis
				}
			} else {
				switch(cmd) {
				case "logout":
					// TODO: O que fazer?
					logedIn = false;
					break;
				case "cd":
					current_path = changeDir(in, current_path);
					break;
				case "exit":
					exit = true;
					break;
				default:
					System.out.println("Unsupported operation!");
					// TODO: Apresnetar lista de comandos disponiveis
				}
			}

		}

		System.out.println("Exiting...");
		//	in.close();
	}

	private static String changeDir(Scanner in, String current_path) {
		String path = in.nextLine().trim();

		Path p = Paths.get(current_path);

		String folders[] = path.split("/");

		String final_path = "";
		for(String current_folder : folders) {
			if(current_folder.equals(".."))
				final_path = p.getParent().toString();
			else if(current_folder.equals("."))
				final_path = p.toString();
			else
				final_path = p.resolve(current_folder).toString();
		}

		return final_path;
	}

	private static String login(Scanner in, RemoteFileServiceClient client) {
		String username = in.nextLine().trim();

		System.out.print(String.format("Enter password for %s : ", username));

		String password = in.nextLine();

		boolean anthenticated = client.login(username, password);

		/*
		if(requestLogin(username, password)){
		 	get token somehow
		 	System.out.println("Login Successful");
			return true;
		}

		System.err.println("Authentication error!");
		return fasle; 			 	
		 */

		return username;
	}

}
