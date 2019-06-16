package token;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Map;

public interface Token {

	public long getExpiration_date();

	public byte[] getSignature();
	
	public String getBase64();
	
	public boolean isExpired(long current_time);
	
	public boolean isAuthentic(Signature sig, PublicKey pubKey) throws InvalidKeyException, SignatureException;

	public boolean isValid(long current_time, Signature sig, PublicKey pubKey) throws InvalidKeyException, SignatureException;
	
	public byte[] serialize() throws IOException;
	
	public Map<String, String> getAdditional_attributes();
	
	public byte[] getPayload();
	
	public String toString();
}
