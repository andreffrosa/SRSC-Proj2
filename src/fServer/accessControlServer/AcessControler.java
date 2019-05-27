package fServer.accessControlServer;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;

public interface AcessControler {

	/**
	 * Used to assure if a user can read files or not.
	 * @return True if the user can read files, False otherwise.
	 */
	@GET
	@Path("/read/{username}")
	
	public boolean canRead(@PathParam("username") String username);
	
	/**
	 * Used to assure if a user can write files or not.
	 * @return True if the user can write files, False otherwise.
	 */
	public boolean canWrite(String username);
	
		
}
