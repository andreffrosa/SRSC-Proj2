package fServer.authServer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class User {

	private String username;
	private String email;
	private String name;
	private String password;
	private boolean allowed;
	
	public User(String username, String email, String name, String password, boolean allowed) {
		this.username = username;
		this.email = email;
		this.name = name;
		this.password = password;
		this.allowed = allowed;
	}

	public String getUsername() {
		return username;
	}

	public String getEmail() {
		return email;
	}

	public String getName() {
		return name;
	}

	public String getPassword() {
		return password;
	}

	public boolean isAllowed() {
		return allowed;
	}
	
	public String toString() {
		return username + ":" + email + ":" + name + ":" + password + ":" + allowed;
	}
	
	public static Map<String,User> parseAuthenticationTable(String path) throws IOException {
		
		Stream<String> lines = Files.lines(Paths.get(path));
	
		List<User> users_list = lines.filter(s -> s.length() > 0 || (s.trim().charAt(0) != '#') )
				.map(line -> {
					String[] s = line.split(":");
					return new User(s[0], s[1], s[2], s[3], Boolean.parseBoolean(s[4]));
					})
				.collect( Collectors.toList() );
		
		Map<String,User> users = new HashMap<>();
		for(User u : users_list) {
			users.put(u.username, u);
			users.put(u.email, u);
		}
		
		lines.close();
		
		return users;
	}
	
}
