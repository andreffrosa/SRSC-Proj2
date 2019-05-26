package fServer.authServer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import utility.Cryptography;

public class AuthenticationToken {

	private String username;
	private long expiration_date;
	private byte[] signature;
	private byte[] payload;
	Map<String,String> additional_attributes;

	private AuthenticationToken(String username, long expiration_date, byte[] payload, byte[] signature, Map<String, String> additional_attributes) {
		this.username = username;
		this.expiration_date = expiration_date;
		this.payload = payload;
		this.signature = signature;
		this.additional_attributes = additional_attributes;
	}

	public String getUsername() {
		return username;
	}

	public long getExpiration_date() {
		return expiration_date;
	}

	public byte[] getSignature() {
		return signature;
	}

	public byte[] getPayload() {
		return payload;
	}

	public Map<String, String> getAdditional_attributes() {
		return additional_attributes;
	}
	
	@Override
	public String toString() {
		StringBuilder s = new StringBuilder();
		s.append(username);
		s.append(':');
		s.append(expiration_date);
		
		for(Entry<String,String> e : additional_attributes.entrySet()) {
			s.append(':');
			s.append(e.getKey());
			s.append('=');
			s.append(e.getValue());
		}
		
		s.append(':');
		s.append(java.util.Base64.getEncoder().encodeToString(signature));
		
		return s.toString();
	}
	
	public boolean isExpired(long current_time) {
		return expiration_date < current_time;
	}
	
	public boolean isAuthentic(Signature sig, PublicKey pubKey) throws InvalidKeyException, SignatureException {
		return Cryptography.validateSignature(sig, pubKey, payload, signature);
	}

	public boolean isValid(long current_time, Signature sig, PublicKey pubKey) throws InvalidKeyException, SignatureException {
		return !isExpired(current_time) && isAuthentic(sig, pubKey);
	}
	
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

	public static AuthenticationToken parseToken(byte[] raw_token) throws IOException {
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

		String username = dataIn.readUTF();
		long expiration_date = dataIn.readLong();

		int n_attributes = dataIn.readInt();
		
		Map<String,String> additional_attributes = new HashMap<>(n_attributes);
		for(int i = 0; i < n_attributes; i++) {
			String key = dataIn.readUTF();
			String value = dataIn.readUTF();
			additional_attributes.put(key, value);
		}

		dataIn.close();
		byteIn.close();

		return new AuthenticationToken(username, expiration_date, payload, signature, additional_attributes);
	}

	public static AuthenticationToken newToken(String username, long expiration_date, Map<String,String> additional_attributes, Signature sig, PrivateKey privKey) throws InvalidKeyException, SignatureException, IOException {

		additional_attributes = (additional_attributes == null) ? new HashMap<>(1) : additional_attributes;

		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeUTF(username);
		dataOut.writeLong(expiration_date);
		dataOut.writeInt(additional_attributes.size());
		
		for(Entry<String,String> e : additional_attributes.entrySet()) {
			dataOut.writeUTF(e.getKey());
			dataOut.writeUTF(e.getValue());
		}

		dataOut.flush();
		byteOut.flush();

		byte[] payload = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();
		
		byte[] signature = Cryptography.sign(sig, privKey, payload);
		
		return new AuthenticationToken(username, expiration_date, payload, signature, additional_attributes);
	}

}
