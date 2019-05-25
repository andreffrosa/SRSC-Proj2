package client;

import java.io.Console;


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

		//	Scanner in = new Scanner(System.in);
		Console console = System.console();
		if (console == null) {
			System.out.println("Couldn't get Console instance");
			System.exit(-1);
		}


		// Receive from args the location of the configuration files
		//TODO

		//Request login data
		if(!loginIn(console))
			System.exit(-1);

		// Process user commands
		String cmd;

		boolean exit = false;
		while(!exit) {
			console.printf("> ");
				cmd = console.readLine();
				
				
				
				switch(cmd) {
					
					case "exit":
					exit = true;
				break;
				}

		}

		System.out.println("Exiting...");
		//	in.close();
	}


	private static boolean loginIn(Console console) {
		//System.out.print("username: ");
		//String username = in.nextLine();
		//System.out.printf("password for %s : ", username);

		console.printf("username: ");
		String username = console.readLine();
		char passwordArray[] = console.readPassword("Enter password for %s : ", username);
		String password = new String(passwordArray);	



		return true;

		/*
		if(requestLogin(username, password)){
		 	get token somehow
		 	System.out.println("Login Successful");
			return true;
		}

		System.err.println("Authentication error!");
		return fasle; 			 	
		 */
	}

}
