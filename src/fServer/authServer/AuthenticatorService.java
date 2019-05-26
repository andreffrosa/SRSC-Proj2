package fServer.authServer;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

@Path(AuthenticatorService.PATH)
public interface AuthenticatorService {

	String PATH = "/auth";
	String CHARSET = ";charset=utf-8";
	
	@GET
	@Path("/requestSession/{username}")
	@Consumes(MediaType.APPLICATION_JSON + CHARSET)
	@Produces(MediaType.APPLICATION_JSON + CHARSET)
	public DH_MSG1 requestSession(@PathParam("username") String username) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException;
	
	@POST
	@Path("/requestToken/{username}/{user_public_value}")
	@Consumes(MediaType.APPLICATION_OCTET_STREAM + CHARSET)
	@Produces(MediaType.APPLICATION_OCTET_STREAM + CHARSET)
	public byte[] requestToken(@PathParam("username") String username, @PathParam("user_public_value") String user_public_value, @QueryParam("client_nonce") long client_nonce, byte[] credentials) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IOException, SignatureException;
	
}
