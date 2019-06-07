/**
 * 
 */
package fServer.mainDispatcher;

import javax.ws.rs.Path;

/**
 * @author Ruben Silva & Andre Rosa
 *
 */

//TODO: Register, Exceptions a enviar

@Path(RemoteFileService.PATH)
public interface RemoteFileService {

	String PATH = "/dispatcher";

}
