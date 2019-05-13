package client;

import java.util.Scanner;

public class Client {

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
