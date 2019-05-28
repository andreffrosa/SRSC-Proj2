/**
 * 
 */
package fServer.mainDispatcher;

import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;	
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * @author Ruben Silva & Andre Rosa
 *
 */

//TODO: Register, Exceptions a enviar

@Path(RemoteFileService.PATH)
public interface RemoteFileService {

	String PATH = "/dispatcher";
	String CHARSET = ";charset=utf-8";
	
	/**
	 * Endpoint that allows users to authenticate themselves.
	 * @param username user username
	 * @param password user password
	 * @return True if everything if correct (and a token on the authorization header), false if credentials are wrong.
	 */
	/*@POST
	@Path("/login/{username}")
	@Consumes(MediaType.APPLICATION_JSON + CHARSET)
	public boolean login(@PathParam("username") String username, String password);*/
	
	/**
	 *  List files or directories on the specified path
	 * @param username user username 
	 * @param path path to list files
	 * @return A list of names of the files and subdirectories on that path.
	 */
	@GET
	@Path("/ls/{username}/{path}")
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public List<String> listFiles(/*@Context*/ Map<String, String>  headers, @PathParam("username") String username, @PathParam("path") String path);
	
	/**
	 * Creates a directory on the specified path.
	 * @param username user username
	 * @param path path to create directory
	 * @return True if everything went correctly or false if the directory was not created.
	 */
	@POST
	@Path("/mkdir/{username}/{path}")
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public boolean mkdir(@PathParam("username") String username, @PathParam("path") String path);
	
	/**
	 * Uploads a file to the specified directory.
	 * @param username user username.
	 * @param path path where to upload file.
	 * @param data file data as byte array.
	 * @return True if everything went correctly or false if the file was not uploaded.
	 */
	@PUT
	@Path("/put/{username}/{path}")
	@Consumes(MediaType.APPLICATION_OCTET_STREAM)
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public boolean upload(@PathParam("username") String username, @PathParam("path") String path, byte[] data );
	
	/**
	 * Downloads a file that resides in the specified directory
	 * @param username user username
	 * @param path file path
	 * @return A byte array with the file data.
	 */
	@GET
	@Path("/get/{username}/{path}")
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
	public byte[] download(@PathParam("username") String username, @PathParam("path") String path);
	
	/**
	 * Copies a file from some path1 to some other path2.
	 * @param username user username.
	 * @param origin path of the file.
	 * @param dest path where to copy to.
	 * @return True if everything went correctly or false if the file was not copied.
	 */
	@PUT
	@Path("/cp/{username}")
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public boolean copy(@PathParam("username") String username, @QueryParam("origin") String origin, @QueryParam("dest") String dest);
	
	/**
	 * Removes a file that resides on the specified path.
	 * @param username user username
	 * @param path path of the file.
	 * @return True if everything went correctly or false if the file was not removed.
	 */
	@DELETE
	@Path("/rm/{username}/{path}")
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public boolean remove(@PathParam("username") String username, @PathParam("path") String path);
	
	/**
	 * Removes a directory with the path provided.
	 * @param username user username
	 * @param path path of the directory
	 * @return True if everything went correctly or false if the directory was not removed.
	 */
	@DELETE
	@Path("/rmdir/{username}/{path}")
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public boolean removeDirectory(@PathParam("username") String username, @PathParam("path") String path);
	
	/**
	 * Retrieved a file metadata
	 * @param username user username
	 * @param path path of the file
	 * @return An object with the info: isDirectory,type, name, creationDate, lastModification
	 */
	@GET
	@Path("/file/{username}/{path}")
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public BasicFileAttributes getFileMetadata(@PathParam("username") String username, @PathParam("path") String path);
}
