package token;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import utility.Cryptography;

public abstract class AbstractToken implements Token {

	protected String encodeToken;
	protected long expiration_date;
	protected byte[] payload;
	protected byte[] signature;
	protected Map<String,String> additional_public_attributes;

	public AbstractToken(long expiration_date, byte[] payload, byte[] signature, Map<String, String> additional_public_attributes) throws IOException {
		this.expiration_date = expiration_date;
		this.payload = payload;
		this.signature = signature;
		this.additional_public_attributes = additional_public_attributes;
		this.encodeToken = encodeToBase64();
	} 

	private String encodeToBase64() throws IOException {
		return Base64.getEncoder().encodeToString(serialize());
	}

	@Override
	public long getExpiration_date() {
		return expiration_date;
	}

	@Override
	public byte[] getSignature() {
		return signature;
	}

	@Override
	public String getBase64() {
		return encodeToken;
	}
	
	@Override
	public Map<String, String> getAdditional_attributes() {
		return additional_public_attributes;
	}

	@Override
	public boolean isExpired(long current_time) {
		return expiration_date < current_time;
	}

	@Override
	public boolean isAuthentic(Signature sig, PublicKey pubKey) throws InvalidKeyException, SignatureException {
		return Cryptography.validateSignature(sig, pubKey, payload, signature);
	}

	@Override
	public boolean isValid(long current_time, Signature sig, PublicKey pubKey)
			throws InvalidKeyException, SignatureException {
		return !isExpired(current_time) && isAuthentic(sig, pubKey);
	}

	@Override
	public byte[] serialize() throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeInt(payload.length);
		dataOut.write(payload);
		dataOut.writeInt(signature.length);
		dataOut.write(signature);

		dataOut.flush();
		byteOut.flush();

		byte[] raw_token = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();

		return raw_token;
	}

	public byte[] getPayload() {
		return payload;
	}
	
	@Override
	public String toString() {
		StringBuilder s = new StringBuilder();
		
		s.append(expiration_date);
		s.append(':');
		s.append(java.util.Base64.getEncoder().encodeToString(signature));
		
		for(Entry<String,String> e : additional_public_attributes.entrySet()) {
			s.append(':');
			s.append(e.getKey());
			s.append('=');
			s.append(e.getValue());
		}
		
		return s.toString();
	}
	
	public static Token parseToken(String base64_token) throws IOException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		return parseToken(java.util.Base64.getDecoder().decode(base64_token));
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

		return new AbstractToken(expiration_date, payload, signature, additional_public_attributes) {};
	}
	
}
