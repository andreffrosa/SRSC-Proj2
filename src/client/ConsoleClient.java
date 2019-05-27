package client;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Scanner;

import utility.ArrayUtil;
import utility.IO;
import utility.MyKeyStore;
import utility.TLS_Utils;

public class ConsoleClient {

	// err
	private static final String UNSUPPORTED_OPERATION = "Unsupported operation!";
	private static final String EXIT_TO_LEAVE = "Or enter exit, to leave";
	private static final String USAGE_LOGIN_USERNAME = "Usage: login <username>";
	private static final String NOT_LOGIN_ERR = "Please login to have access to the system.";

	// Operations
	private static final String LOGOUT = "logout";
	private static final String LOGIN = "login";
	private static final String CHANGE_DIR = "cd";
	private static final String LIST_FILES = "ls";
	private static final String NEW_DIRECTORY = "mkdir";
	private static final String UPLOAD = "put";
	private static final String DOWNLOAD = "get";
	private static final String COPY = "cp";
	private static final String REMOVE_FILE = "rm";
	private static final String REMOVE_DIR = "rmdir";
	private static final String FILE_METADATA = "file";
	private static final String EXIT = "exit";
	private static final String LOCAL_STORAGE = "./Files";

	static RemoteFileServiceClient client;
	static String username;

	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
	FileNotFoundException, IOException, UnrecoverableKeyException, KeyManagementException {

		if (args.length < 3) {
			System.err.println("Usage: ConsoleClient <server-location> <keystore-configs> <login-configs>");
			System.exit(-1);
		}

		String location = args[0];
		String ks_path = args[1];
		String login_configs = args[2];

		MyKeyStore[] kstores = TLS_Utils.loadKeyStores(ks_path);

		byte[] iv = ArrayUtil.unparse(IO.loadProperties(login_configs).getProperty("IV"));
		
		client = new RemoteFileServiceClient(kstores[0].getKeystore(), kstores[0].getPassword(),
				kstores[1].getKeystore(), location, iv);

		Scanner in = new Scanner(System.in);

		String current_path = "";
		boolean logedIn = false;

		// Process user commands
		String cmd;
		boolean exit = false;

		username = "";

		while (!exit) {
			System.out.print(username + "$" + current_path + "> ");
			cmd = in.next().toLowerCase();

			if (!logedIn) {
				switch (cmd) {
				case LOGIN:
					username = login(in, client);
					if (username != null) {
						current_path = "/";
						logedIn = true;
					}
					break;
				case EXIT:
					exit = true;
					break;
				default:
					System.err.println(NOT_LOGIN_ERR);
					System.out.println(USAGE_LOGIN_USERNAME);
					System.out.println(EXIT_TO_LEAVE);
				}
			} else {
				switch (cmd) {
				case CHANGE_DIR:
					current_path = changeDir(in, current_path);
					break;
				case LIST_FILES:
					listFiles(current_path);
					break;
				case NEW_DIRECTORY:
					mkdir(current_path, in);
					break;
				case UPLOAD:
					upload(current_path, in);
					break;
				case DOWNLOAD:
					download(current_path, in);
					break;
				case COPY:
					copy(current_path, in);
					break;
				case REMOVE_FILE:
					rmFile(current_path, in);
					break;
				case REMOVE_DIR:
					rmDir(current_path, in);
					break;
				case FILE_METADATA:
					getFileData(current_path, in);
					break;
				case LOGOUT:
					// TODO
					username = "";
					current_path = "";
					logedIn = false;
					break;
				case EXIT:
					exit = true;
					break;
				default:
					System.out.println(UNSUPPORTED_OPERATION);
					listCmds();
				}
			}
		}

		System.out.println("Exiting...");

		in.close();
	}

	private static void getFileData(String current_path, Scanner in) {
		// TODO Auto-generated method stub

	}

	private static void rmDir(String current_path, Scanner in) {
		String dirName = in.nextLine();
		if(!client.removeDirectory(username, String.format("%s/%s", current_path, dirName)))
			System.out.println("Error Deliting file: " + dirName);
		
	}

	private static void rmFile(String current_path, Scanner in) {
		String fileNameString = in.nextLine();
		if(!client.remove(username, String.format("%s/%s", current_path, fileNameString)))
			System.out.println("Error Deliting file: " + fileNameString);

	}

	private static void copy(String current_path, Scanner in) {

		String fileName = in.next();
		String dest = in.nextLine();
		client.copy(username, String.format("%s/%s", current_path, fileName), String.format("/%s/%s", username, dest));

	}

	private static void download(String current_path, Scanner in) throws IOException {
		String fileName = in.nextLine();
		Path localFilePath = Paths.get(LOCAL_STORAGE, fileName);
		byte[] data = client.download(username, String.format("%s/%s", current_path, fileName));

		if (data != null)
			Files.write(localFilePath, data);
		else
			System.out.println("File not found");
	}

	private static void upload(String current_path, Scanner in) {

		String fileName = in.nextLine();
		Path localFilePath = Paths.get(String.format("%s/%s", LOCAL_STORAGE, fileName));
		byte[] data = null;
		try {
			if (Files.exists(localFilePath) && Files.isReadable(localFilePath))
				data = Files.readAllBytes(localFilePath);
			client.upload(username, String.format("%s/%s", current_path, fileName), data);
		} catch (IOException e) {
			System.out.println("Could Not Found File " + fileName);
		}

	}

	private static void mkdir(String current_path, Scanner in) {
		
		String dirName = String.format("%s/%s/", current_path, in.nextLine().trim());
		if (!client.mkdir(username, dirName))
			System.out.println("Impossible to create directory");

	}

	private static void listFiles(String current_path) {

		List<String> files = client.listFiles(username, current_path);
		files.forEach(System.out::println);

	}

	private static void listCmds() {

		System.out.println("Change directory: cd <path>");
		System.out.println("List files: ls");
		System.out.println("New Directory: mkdir <path>");
		System.out.println("Upload file to path: put <file> <path>");
		System.out.println("Download file: get <pathToFile>");
		System.out.println("Copy file: cp <origin> <destination>");
		System.out.println("Remove file: rm <pathToFile>");
		System.out.println("Remove Directory: rmdir <path>");
		System.out.println("Get metadata: file <pathToFile>");
	}

	private static String changeDir(Scanner in, String current_path) {
		String path = in.nextLine().trim();

		Path p = Paths.get(current_path);

		String folders[] = path.split("/");

		String final_path = "";
		for (String current_folder : folders) {
			if (current_folder.equals(".."))
				final_path = p.getParent().toString();
			else if (current_folder.equals("."))
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
		
		client.login(username, password);

		// boolean anthenticated = client.login(username, password);

		/*
		 * if(requestLogin(username, password)){ get token somehow
		 * System.out.println("Login Successful"); return true; }
		 * 
		 * System.err.println("Authentication error!"); return fasle;
		 */

		return username;
	}

}
