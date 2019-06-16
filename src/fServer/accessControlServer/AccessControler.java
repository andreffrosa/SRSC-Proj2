package fServer.accessControlServer;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

import http.MediaType;
import rest.RestResponse;

@Path(AccessControler.PATH)
public interface AccessControler {
	
	public static final String PATH = "/access";
	
	public static final String WRITE_ACCESS_REQUEST = "write";
	public static final String READ_ACCESS_REQUEST = "read";
	
	/**
	 * Used to assure if a user can read files or not.
	 * @return True if the user can read files, False otherwise.
	 * @throws SignatureException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws ShortBufferException 
	 * @throws NoSuchProviderException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 */
	@GET
	@Path("/{username}/{op_type}/{op_params}/{nonce}")
	@Produces(MediaType.APPLICATION_JSON)
	public RestResponse hasAccess(@HeaderParam("Authorization") String auth_token,  @PathParam("username") String username, @PathParam("op_type") String operation, @PathParam("op_params") String params, @PathParam("nonce") long nonce) throws InvalidKeyException, SignatureException, IOException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException;
		
}
