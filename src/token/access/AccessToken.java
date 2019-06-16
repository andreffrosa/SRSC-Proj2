package token.access;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import token.AbstractToken;
import token.Token;
import utility.Cryptography;

public class AccessToken extends AbstractToken {
	
	private byte[] hash;

	private AccessToken(byte[] hash, long expiration_date, byte[] payload, byte[] signature, Map<String, String> additional_public_attributes) throws IOException {
		super(expiration_date, payload, signature, additional_public_attributes);
		this.hash = hash;
	} 
	
	public byte[] getHash() {
		return hash;
	}

	public static AccessToken parseToken(String base64_token) throws IOException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		return (AccessToken) parseToken(java.util.Base64.getDecoder().decode(base64_token));
	}
	
	public static Token parseToken(byte[] raw_token) throws IOException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		ByteArrayInputStream byteIn = new ByteArrayInputStream(raw_token);
		DataInputStream dataIn = new DataInputStream(byteIn);

		int payload_size = dataIn.readInt();
		byte[] payload = new byte[payload_size];
		dataIn.read(payload, 0, payload_size);

		int signature_size = dataIn.readInt();
		byte[] signature = new byte[signature_size];
		dataIn.read(signature, 0, signature_size);

		dataIn.close();
		byteIn.close();

		byteIn = new ByteArrayInputStream(payload);
		dataIn = new DataInputStream(byteIn);

		int len = dataIn.readInt();
		byte[] hash = new byte[len];
		dataIn.read(hash, 0, len);
		
		long expiration_date = dataIn.readLong();

		int n_public_attributes = dataIn.readInt();
		Map<String,String> additional_public_attributes = new HashMap<>(n_public_attributes);
		for(int i = 0; i < n_public_attributes; i++) {
			String key = dataIn.readUTF();
			String value = dataIn.readUTF();
			additional_public_attributes.put(key, value);
		}

		dataIn.close();
		byteIn.close();

		return new AccessToken(hash, expiration_date, payload, signature, additional_public_attributes);
	}
	
	public static AccessToken newToken(byte[] hash, long expiration_date, Map<String,String> additional_public_attributes, Signature sig, PrivateKey privKey) throws InvalidKeyException, SignatureException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {

		additional_public_attributes = (additional_public_attributes == null) ? new HashMap<>(1) : additional_public_attributes;

		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeInt(hash.length);
		dataOut.write(hash, 0, hash.length);

		dataOut.writeLong(expiration_date);

		dataOut.writeInt(additional_public_attributes.size());
		for(Entry<String,String> e : additional_public_attributes.entrySet()) {
			dataOut.writeUTF(e.getKey());
			dataOut.writeUTF(e.getValue());
		}

		dataOut.flush();
		byteOut.flush();

		byte[] payload = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();

		byte[] signature = Cryptography.sign(sig, privKey, payload);

		return new AccessToken(hash, expiration_date, payload, signature, additional_public_attributes);
	}

	
}
