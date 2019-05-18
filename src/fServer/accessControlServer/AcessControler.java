package fServer.accessControlServer;

public interface AcessControler {

	/**
	 * Used to assure if a user can read files or not.
	 * @return True if the user can read files, False otherwise.
	 */
	public boolean canRead(String username);
	
	/**
	 * Used to assure if a user can write files or not.
	 * @return True if the user can write files, False otherwise.
	 */
	public boolean canWrite(String username);
	
		
}
