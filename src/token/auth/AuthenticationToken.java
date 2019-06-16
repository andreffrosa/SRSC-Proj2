package token.auth;

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
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import token.AbstractToken;
import utility.Cryptography;

public class AuthenticationToken extends AbstractToken {

	private String username;
	private byte[] encrypted_private_attributes;
	private Map<String,String> additional_private_attributes;

	private AuthenticationToken(String username, long expiration_date, byte[] payload, byte[] signature, byte[] encrypted_private_attributes, Map<String, String> additional_public_attributes, Map<String, String> additional_private_attributes) throws IOException {
		super(expiration_date, payload, signature, additional_public_attributes);
		this.username = username;
		this.encrypted_private_attributes = encrypted_private_attributes;
		this.additional_private_attributes = additional_private_attributes;
	}

	public byte[] getEncrypted_private_attributes() {
		return encrypted_private_attributes;
	}

	public Map<String, String> getAdditional_private_attributes() {
		return additional_private_attributes;
	}

	public String getUsername() {
		return username;
	}

	@Override
	public String toString() {

		StringBuilder s = new StringBuilder();
		s.append(username);
		s.append(':');
		s.append(super.toString());

		if(additional_private_attributes != null) {
			for(Entry<String,String> e : additional_private_attributes.entrySet()) {
				s.append(':');
				s.append(e.getKey());
				s.append('=');
				s.append(e.getValue());
			}
		} else {
			s.append(':');
			s.append(java.util.Base64.getEncoder().encodeToString(encrypted_private_attributes));
		}

		return s.toString();
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
