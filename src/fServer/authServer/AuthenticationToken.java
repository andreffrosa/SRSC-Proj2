package fServer.authServer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import utility.ArrayUtil;
import utility.Cryptography;

public class AuthenticationToken {

	private String encodeToken;
	private String username;
	private long expiration_date;
	private byte[] signature;
	private byte[] payload;
	private byte[] encrypted_private_attributes;
	private Map<String,String> additional_public_attributes;
	private Map<String,String> additional_private_attributes;

	private AuthenticationToken(String username, long expiration_date, byte[] payload, byte[] signature, byte[] encrypted_private_attributes, Map<String, String> additional_public_attributes, Map<String, String> additional_private_attributes) throws IOException {
		this.username = username;
		this.expiration_date = expiration_date;
		this.payload = payload;
		this.signature = signature;
		this.encrypted_private_attributes = encrypted_private_attributes;
		this.additional_public_attributes = additional_public_attributes;
		this.additional_private_attributes = additional_private_attributes;
		encodeToken = encodeToBase64( );
	}
	
	public byte[] getEncrypted_private_attributes() {
		return encrypted_private_attributes;
	}

	public Map<String, String> getAdditional_private_attributes() {
		return additional_private_attributes;
	}

	private String encodeToBase64() throws IOException {
		return Base64.getEncoder().encodeToString(serialize());
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
	
	public String getBase64() {
		return encodeToken;
	}

	public Map<String, String> getAdditional_attributes() {
		return additional_public_attributes;
	}
	
	@Override
	public String toString() {
		StringBuilder s = new StringBuilder();
		s.append(username);
		s.append(':');
		s.append(expiration_date);
		
		for(Entry<String,String> e : additional_public_attributes.entrySet()) {
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
	
	public static AuthenticationToken parseToken(String base64_token, Cipher decryptCipher) throws IOException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		return parseToken(java.util.Base64.getDecoder().decode(base64_token), decryptCipher);
	}

	public static AuthenticationToken parseToken(byte[] raw_token, Cipher decryptCipher) throws IOException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
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

		int n_public_attributes = dataIn.readInt();
		Map<String,String> additional_public_attributes = new HashMap<>(n_public_attributes);
		for(int i = 0; i < n_public_attributes; i++) {
			String key = dataIn.readUTF();
			String value = dataIn.readUTF();
			additional_public_attributes.put(key, value);
		}
		
		int len = dataIn.readInt();
		byte[] encrypted_private_attributes = new byte[len];
		dataIn.read(encrypted_private_attributes, 0, len);
		
		dataIn.close();
		byteIn.close();
		
		Map<String,String> additional_private_attributes = null;
		if(decryptCipher != null) {
			byte[] decrypted_private_attributes = Cryptography.decrypt(decryptCipher, encrypted_private_attributes);
			byteIn = new ByteArrayInputStream(decrypted_private_attributes);
			dataIn = new DataInputStream(byteIn);
			
			int size = dataIn.readInt();
			additional_private_attributes = new HashMap<String, String>(size);
			for(int i = 0; i < size; i++) {
				String key = dataIn.readUTF();
				String value = dataIn.readUTF();
				additional_private_attributes.put(key, value);
			}
			
			dataIn.close();
			byteIn.close();
		}


		return new AuthenticationToken(username, expiration_date, payload, signature, encrypted_private_attributes, additional_public_attributes, additional_private_attributes);
	}

	public static AuthenticationToken newToken(String username, long expiration_date, Map<String,String> additional_public_attributes, Map<String,String> additional_private_attributes, Signature sig, PrivateKey privKey, Cipher encryptCipher) throws InvalidKeyException, SignatureException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {

		additional_public_attributes = (additional_public_attributes == null) ? new HashMap<>(1) : additional_public_attributes;

		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeUTF(username);
		dataOut.writeLong(expiration_date);
		
		dataOut.writeInt(additional_public_attributes.size());
		for(Entry<String,String> e : additional_public_attributes.entrySet()) {
			dataOut.writeUTF(e.getKey());
			dataOut.writeUTF(e.getValue());
		}
		
		byte[] private_payload = buildPrivatePayload(additional_private_attributes, encryptCipher);
		dataOut.writeInt(private_payload.length);
		dataOut.write(private_payload, 0, private_payload.length);

		dataOut.flush();
		byteOut.flush();

		byte[] payload = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();
				
		byte[] signature = Cryptography.sign(sig, privKey, payload);
		
		return new AuthenticationToken(username, expiration_date, payload, signature, private_payload, additional_public_attributes, null);
	}
	
	private static byte[] buildPrivatePayload(Map<String,String> additional_private_attributes, Cipher encryptCipher) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);
		
		dataOut.writeInt(additional_private_attributes.size());
		for(Entry<String,String> e : additional_private_attributes.entrySet()) {
			dataOut.writeUTF(e.getKey());
			dataOut.writeUTF(e.getValue());
		}

		dataOut.flush();
		byteOut.flush();

		byte[] private_payload = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();
		
		return Cryptography.encrypt(encryptCipher, private_payload);
	}

}
