package client;

import java.util.Scanner;

public class Client {

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
	
	
	public static void main(String[] args) {
		
		// Receive from args the location of the configuration files
		
		// Process user commands
		Scanner in = new Scanner(System.in);
		
		String cmd;
		
		boolean exit = false;
		while(!exit) {
			System.out.print("> ");
			cmd = in.next();
			
			switch(cmd) {
			case "login":
				String username = in.next();
				String password = in.next();
				break;
			case "exit":
				exit = true;
				break;
			}
			
			in.nextLine();
		}
		
		System.out.println("Exiting...");
		in.close();
	}
	
}
