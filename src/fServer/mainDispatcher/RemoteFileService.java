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

}
