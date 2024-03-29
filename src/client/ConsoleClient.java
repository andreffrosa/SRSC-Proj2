package client;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import client.exception.FileNotFoundException;
import client.exception.LogginRequieredException;
import client.exception.UnautorizedException;
import fServer.authServer.exceptions.DeniedAccessException;
import fServer.authServer.exceptions.WrongChallengeAnswerException;
import token.ExpiredTokenException;
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

	static EncryptedRemoteFileServiceClient client;
	static String username;

	public static void main(String[] args) throws Exception {

		if (args.length < 4) {
			System.err.println("Usage: ConsoleClient <server-location> <keystore-configs> <login-configs> <encrypted-fs-confgis>");
			System.exit(-1);
		}

		String location = args[0];
		String ks_path = args[1];
		String login_configs = args[2];
		String encrypted_fs_configs = args[3];

		MyKeyStore[] kstores = TLS_Utils.loadKeyStores(ks_path);

		LoginUtility login_util = LoginUtility.fromConfig(login_configs);

		client = new EncryptedRemoteFileServiceClient(encrypted_fs_configs, kstores[0].getKeystore(), kstores[0].getPassword(),
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
					username = login(in);
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
					
					client.logout();
					username = "";
					current_path = "";
					logedIn = false;
					break;
				case EXIT:
					exit = true;
					break;
				default:
					in.nextLine();
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
		String bfa = null;
		
		try {
			bfa = client.getFileMetadata(username, fileName);
		
		} catch (LogginRequieredException e) {
			System.out.println("Error: You are not logged in.");
		} catch (UnautorizedException e) {
			System.out.println("Error: You don't have permission for that operation");
		} catch (FileNotFoundException e) {
			System.out.println("Error: That file does not exist.");
		}catch(Exception e) {
			System.out.println("Unexpected error: " + e.getMessage());
		}
		
		if(bfa != null) {
			System.out.println(bfa.toString());
		}
	}

	private static void rmDir(String current_path, Scanner in) {
		String dirName = IO.resolvePath(current_path, in.nextLine().trim());
		try {
			if(!client.removeDirectory(username, dirName))
				System.out.println("Error Deleting directory: " + dirName);
		} catch (LogginRequieredException e) {
			System.out.println("Error: You are not logged in.");
		} catch (UnautorizedException e) {
			System.out.println("Error: You don't have permission for that operation");
		} catch (FileNotFoundException e) {
			System.out.println("Error: That directory does not exist.");
		}catch(Exception e) {
			System.out.println("Unexpected error: " + e.getMessage());
		}
	}

	private static void rmFile(String current_path, Scanner in) {
		String fileNameString = IO.resolvePath(current_path, in.nextLine().trim());
		try {
			if(!client.remove(username, fileNameString))
				System.out.println("Error Deliting file: " + fileNameString);
		} catch (LogginRequieredException e) {
			System.out.println("Error: You are not logged in.");
		} catch (UnautorizedException e) {
			System.out.println("Error: You don't have permission for that operation");
		} catch (FileNotFoundException e) {
			System.out.println("Error: That file does not exist.");
		}catch(Exception e) {
			System.out.println("Unexpected error: " + e.getMessage());
		}

	}

	private static void copy(String current_path, Scanner in) {

		String src = IO.resolvePath(current_path, in.next().trim());
		String dest = IO.resolvePath(current_path, in.nextLine().trim());

		try {
			client.copy(username, src, dest);
			
		} catch (LogginRequieredException e) {
			System.out.println("Error: You are not logged in.");
		} catch (UnautorizedException e) {
			System.out.println("Error: You don't have permission for that operation");
		} catch (FileNotFoundException e) {
			System.out.println("Error: That file does not exist.");
		}catch(Exception e) {
			System.out.println("Unexpected error: " + e.getMessage());
		}
	}

	private static void download(String current_path, Scanner in) throws IOException {

		String remote_file = IO.resolvePath(current_path, in.next().trim());
		String local_file = IO.resolvePath(LOCAL_STORAGE, in.nextLine().trim());
		byte[] data = null;

		try {
			data = client.download(username, remote_file);
		} catch (LogginRequieredException e) {
			System.out.println("Error: You are not logged in.");
		} catch (UnautorizedException e) {
			System.out.println("Error: You don't have permission for that operation");
		} catch (FileNotFoundException e) {
			System.out.println("Error: That file does not exist.");
		}catch(Exception e) {
			System.out.println("Unexpected error: " + e.getMessage());
		}

		if (data != null)
			Files.write(Paths.get(local_file), data);
		else
			System.out.println("File not found");
	}

	private static void upload(String current_path, Scanner in) {

		String local_file = IO.resolvePath(LOCAL_STORAGE, in.next().trim());
		String remote_file = IO.resolvePath(current_path, in.nextLine().trim());
		byte[] data = null;
		
		try {
			Path p = Paths.get(local_file);
			if (Files.exists(p) && Files.isReadable(p))
				data = Files.readAllBytes(p);
			client.upload(username, remote_file, data);
		} catch (IOException e) {
			System.out.println("Could Not Found File " + local_file);
		} catch (LogginRequieredException e) {
			System.out.println("Error: You are not logged in.");
		} catch (UnautorizedException e) {
			System.out.println("Error: You don't have permission for that operation");
		} catch(Exception e) {
			System.out.println("Unexpected error: " + e.getMessage());
		}
	}

	private static void mkdir(String current_path, Scanner in) {

		String path = IO.resolvePath(current_path, in.nextLine().trim());

		try {
			if (!client.mkdir(username, path))
				System.out.println("Impossible to create directory");

		} catch (LogginRequieredException e) {
			System.out.println("Error: You are not logged in.");
		} catch (UnautorizedException e) {
			System.out.println("Error: You don't have permission for that operation");
		} catch(Exception e) {
			e.printStackTrace();
			System.out.println("Unexpected error: " + e.getMessage());
		}

	}

	private static void listFiles(String current_path, Scanner in) {

		List<String> files;
		String path = in.nextLine();

		try {

			if(path.equals(""))
				files = client.listFiles(username, current_path);
			else
				files = client.listFiles(username, IO.resolvePath(current_path, path));

			files.forEach( f -> System.out.println("\t" + f));

		} catch (LogginRequieredException e) {
			System.out.println("Error: You are not logged in.");
		} catch (UnautorizedException e) {
			System.out.println("Error: You don't have permission for that operation");
		} catch (FileNotFoundException e) {
			System.out.println("Error: That file does not exist.");
		}catch(Exception e) {
			System.out.println("Unexpected error: " + e.getMessage());
		}
	}
	
	private static String login(Scanner in) {

		String username = in.nextLine().trim();
		System.out.print(String.format("Enter password for %s : ", username));

		String password = in.nextLine();

		boolean result = false;

			try {
				result = client.login(username, password);
			} catch (ExpiredTokenException e) {
				System.out.println("Session expired, please login again");
			} catch (WrongChallengeAnswerException e) {
				System.out.println("Error: Wrong password");
			} catch (DeniedAccessException e) {
				System.out.println("You don't have permissions for that operation");
			}

			username = client.getToken().getUsername();

			System.out.println("\n\tWelcome " + client.getToken().getAdditional_private_attributes().get("name") + "!");


		return result ? username : null;
	}
	
	private static void listCmds() {
		System.out.println("Change directory: cd <path>");
		System.out.println("List files: ls");
		System.out.println("New Directory: mkdir <path>");
		System.out.println("Upload file to path: put <file> <path>");
		System.out.println("Download file: get <pathToFile>");
		System.out.println("Copy file: cp <origin> <destination>");
		System.out.println("Remove file: rm <pathToFile> <downloadDest>");
		System.out.println("Remove Directory: rmdir <path>");
		System.out.println("Get metadata: file <pathToFile>");
	}
	
	private static String changeDir(Scanner in, String current_path) {
		String path = in.nextLine().trim();
		return IO.resolvePath(current_path, path);
	}
}
