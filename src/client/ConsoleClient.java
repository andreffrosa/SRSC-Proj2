package client;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import fServer.authServer.DeniedAccessException;
import fServer.authServer.ExpiredTokenException;
import fServer.authServer.WrongChallengeAnswerException;
import utility.IO;
import utility.LoginUtility;
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

	public static void main(String[] args) throws Exception {

		if (args.length < 3) {
			System.err.println("Usage: ConsoleClient <server-location> <keystore-configs> <login-configs>");
			System.exit(-1);
		}

		String location = args[0];
		String ks_path = args[1];
		String login_configs = args[2];

		MyKeyStore[] kstores = TLS_Utils.loadKeyStores(ks_path);

		LoginUtility login_util = LoginUtility.fromConfig(login_configs);
		
		client = new RemoteFileServiceClient(kstores[0].getKeystore(), kstores[0].getPassword(),
				kstores[1].getKeystore(), location, login_util);

		Scanner in = new Scanner(System.in);

		String current_path = "";
		boolean logedIn = false;

		// Process user commands
		String cmd;
		boolean exit = false;

		username = "";

		System.out.println( "Remote File Storage Service " + (new Date()).toString());
		
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
					} else
						username = "";
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
					listFiles(current_path, in);
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
					client.logout();
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
		String fileName = IO.resolvePath(current_path, in.nextLine().trim());
		String bfa = client.getFileMetadata(username, fileName);
		if(bfa != null) {
			System.out.println(bfa.toString()); //check if this is good
		}
	}

	private static void rmDir(String current_path, Scanner in) {
		String dirName = IO.resolvePath(current_path, in.nextLine().trim());
		if(!client.removeDirectory(username, dirName))
			System.out.println("Error Deleting file: " + dirName);
	}

	private static void rmFile(String current_path, Scanner in) {
		String fileNameString = IO.resolvePath(current_path, in.nextLine().trim());
		if(!client.remove(username, fileNameString))
			System.out.println("Error Deliting file: " + fileNameString);

	}

	private static void copy(String current_path, Scanner in) {

		String src = IO.resolvePath(current_path, in.next().trim());
		String dest = IO.resolvePath(current_path, in.nextLine().trim());
		
		client.copy(username, src, dest);
	}

	private static void download(String current_path, Scanner in) throws IOException {
		
		String remote_file = IO.resolvePath(current_path, in.next().trim());
		String local_file = IO.resolvePath(LOCAL_STORAGE, in.nextLine().trim());
		
		byte[] data = client.download(username, remote_file);

		if (data != null)
			Files.write(Paths.get(local_file), data);
		else
			System.out.println("File not found");
		
		/*String fileName = IO.resolvePath(current_path, in.nextLine());
		Path localFilePath = Paths.get(LOCAL_STORAGE, fileName);
		byte[] data = client.download(username, String.format("%s/%s", current_path, fileName));

		if (data != null)
			Files.write(localFilePath, data);
		else
			System.out.println("File not found");*/
	}

	private static void upload(String current_path, Scanner in) {

		String local_file = IO.resolvePath(LOCAL_STORAGE, in.next().trim());
		String remote_file = IO.resolvePath(current_path, in.nextLine().trim());
		
		System.out.println(local_file);
		System.out.println(remote_file);
		byte[] data = null;
		try {
			Path p = Paths.get(local_file);
			if (Files.exists(p) && Files.isReadable(p))
				data = Files.readAllBytes(p);
			
			client.upload(username, remote_file, data);
		} catch (IOException e) {
			System.out.println("Could Not Found File " + local_file);
		}
		
		
		/*String fileName = IO.resolvePath("./", in.nextLine());
		Path localFilePath = Paths.get(String.format("%s/%s", LOCAL_STORAGE, fileName));
		byte[] data = null;
		try {
			if (Files.exists(localFilePath) && Files.isReadable(localFilePath))
				data = Files.readAllBytes(localFilePath);
			System.out.println(new String(data));
			System.out.println(String.format("%s/%s", current_path, fileName));
			client.upload(username, String.format("%s/%s", current_path, fileName), data);
		} catch (IOException e) {
			System.out.println("Could Not Found File " + fileName);
		}
*/
		
	}

	private static void mkdir(String current_path, Scanner in) {
		
		String path = IO.resolvePath(current_path, in.nextLine().trim());
		
		String dirName = String.format("%s/%s/", current_path, path);
		if (!client.mkdir(username, dirName))
			System.out.println("Impossible to create directory");

	}

	private static void listFiles(String current_path, Scanner in) {

		List<String> files;
		
		String path = in.nextLine();
		if(path.equals(""))
			files = client.listFiles(username, current_path);
		else
			files = client.listFiles(username, IO.resolvePath(current_path, path));
		
		files.forEach( f -> System.out.println("\t" + f));
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

		return IO.resolvePath(current_path, path);
	}

	private static String login(Scanner in, RemoteFileServiceClient client) {

		String username = in.nextLine().trim();
		System.out.print(String.format("Enter password for %s : ", username));

		String password = in.nextLine();
		
		boolean result = false;
		try {
			result = client.login(username, password);
		} catch (ExpiredTokenException | WrongChallengeAnswerException | DeniedAccessException e) {
			System.out.println("\t" + e.getMessage());
			return null;
		}

		return result ? client.getToken().getUsername() : null;
	}

}
