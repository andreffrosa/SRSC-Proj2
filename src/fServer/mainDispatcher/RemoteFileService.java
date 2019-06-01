/**
 * 
 */
package fServer.mainDispatcher;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import rest.RestResponse;

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
	 *  List files or directories on the specified path
	 * @param username user username 
	 * @param path path to list files
	 * @return A list of names of the files and subdirectories on that path.
	 * @throws Exception 
	 */
	@GET
	@Path("/ls/{username}/{path}")
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public RestResponse listFiles(@HeaderParam("Authorization") String token, @PathParam("username") String username, @PathParam("path") String path) throws Exception;
	
	/**
	 * Creates a directory on the specified path.
	 * @param username user username
	 * @param path path to create directory
	 * @return True if everything went correctly or false if the directory was not created.
	 * @throws Exception 
	 */
	@POST
	@Path("/mkdir/{username}/{path}")
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public RestResponse mkdir(@HeaderParam("Authorization") String token, @PathParam("username") String username, @PathParam("path") String path) throws Exception;
	
	/**
	 * Uploads a file to the specified directory.
	 * @param username user username.
	 * @param path path where to upload file.
	 * @param data file data as byte array.
	 * @return True if everything went correctly or false if the file was not uploaded.
	 * @throws Exception 
	 */
	@PUT
	@Path("/put/{username}/{path}")
	@Consumes(MediaType.APPLICATION_OCTET_STREAM)
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public RestResponse upload(@HeaderParam("Authorization") String token, @PathParam("username") String username, @PathParam("path") String path, byte[] data ) throws Exception;
	
	/**
	 * Downloads a file that resides in the specified directory
	 * @param username user username
	 * @param path file path
	 * @return A byte array with the file data.
	 * @throws Exception 
	 */
	@GET
	@Path("/get/{username}/{path}")
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
	public RestResponse download(@HeaderParam("Authorization") String token, @PathParam("username") String username, @PathParam("path") String path) throws Exception;
	
	/**
	 * Copies a file from some path1 to some other path2.
	 * @param username user username.
	 * @param origin path of the file.
	 * @param dest path where to copy to.
	 * @return True if everything went correctly or false if the file was not copied.
	 * @throws Exception 
	 */
	@PUT
	@Path("/cp/{username}")
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public RestResponse copy(@HeaderParam("Authorization") String token, @PathParam("username") String username, @QueryParam("origin") String origin, @QueryParam("dest") String dest) throws Exception;
	
	/**
	 * Removes a file that resides on the specified path.
	 * @param username user username
	 * @param path path of the file.
	 * @return True if everything went correctly or false if the file was not removed.
	 * @throws Exception 
	 */
	@DELETE
	@Path("/rm/{username}/{path}")
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public RestResponse remove(@HeaderParam("Authorization") String token, @PathParam("username") String username, @PathParam("path") String path) throws Exception;
	
	/**
	 * Removes a directory with the path provided.
	 * @param username user username
	 * @param path path of the directory
	 * @return True if everything went correctly or false if the directory was not removed.
	 * @throws Exception 
	 */
	@DELETE
	@Path("/rmdir/{username}/{path}")
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public RestResponse removeDirectory(@HeaderParam("Authorization") String token, @PathParam("username") String username, @PathParam("path") String path) throws Exception;
	
	/**
	 * Retrieved a file metadata
	 * @param username user username
	 * @param path path of the file
	 * @return An object with the info: isDirectory,type, name, creationDate, lastModification
	 * @throws Exception 
	 */
	@GET
	@Path("/file/{username}/{path}")
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public RestResponse getFileMetadata(@HeaderParam("Authorization") String token, @PathParam("username") String username, @PathParam("path") String path) throws Exception;
}
