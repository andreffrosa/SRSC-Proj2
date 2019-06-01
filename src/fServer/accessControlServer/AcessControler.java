package fServer.accessControlServer;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

import http.MediaType;



@Path(AcessControler.PATH)
public interface AcessControler {

	
	public static final String PATH = "/access";
	
	public static final String WRITE_ACCESS_REQUEST = "write";
	public static final String READ_ACCESS_REQUEST = "read";
	
	/**
	 * Used to assure if a user can read files or not.
	 * @return True if the user can read files, False otherwise.
	 */
	@GET
	@Path("/{operation}/{username}")
	@Produces(MediaType.APPLICATION_JSON)
	public boolean hasAccess(@PathParam("operation") String opeartion, @PathParam("username") String username);
	
	
		
}
