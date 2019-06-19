package client.proxy.inodes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import utility.ArrayUtil;
import utility.Cryptography;

public class DataFragment {

	private String name;
	private byte[] data;
	private byte[] padding;
	private byte[] payload;
	private byte[] signature;
	
	public DataFragment(String name, byte[] data, byte[] padding, byte[] payload, byte[] signature) {
		this.name = name;
		this.data = data;
		this.padding = padding;
		this.payload = payload;
		this.signature = signature;
	}
	
	public String getName() {
		return name;
	}

	public byte[] getData() {
		return data;
	}
	
	public byte[] getPayload() {
		return payload;
	}

	public byte[] getPadding() {
		return padding;
	}

	public byte[] getSignature() {
		return signature;
	}
	
	public boolean validateSignature(Signature sig, PublicKey pubKey) throws InvalidKeyException, SignatureException {
		return Cryptography.validateSignature(sig, pubKey, payload, signature);
	}
	
	public byte[] serialize() {
		return ArrayUtil.concat(payload, signature);
	}
	
	public static DataFragment deserialize(String name, byte[] fragment, int encrypted_payload_size, Cipher decryptCipher) throws IOException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		
		byte[] payload = Arrays.copyOf(fragment, encrypted_payload_size);
		byte[] signature = Arrays.copyOfRange(fragment, encrypted_payload_size, fragment.length);
		
		byte[] clear_text = Cryptography.decrypt(decryptCipher, payload);
		
		ByteArrayInputStream byteIn = new ByteArrayInputStream(clear_text);
		DataInputStream dataIn = new DataInputStream(byteIn);

		int padding_len = dataIn.readInt();
		byte[] padding = new byte[padding_len];
		dataIn.read(padding, 0, padding_len);
		
		int data_len = clear_text.length - Integer.BYTES - padding_len;
		byte[] data = new byte[data_len];
		dataIn.read(data, 0, data_len);

		dataIn.close();
		byteIn.close();
		
		return new DataFragment(name, data, padding, payload, signature);
	}
	
	public static int getNfragments(int data_len, int payload_size) {
		int fragment_data_size = payload_size - Integer.BYTES;
		int n_fragments = (data_len / fragment_data_size) + (data_len % fragment_data_size == 0 ? 0 : 1);
		return n_fragments;
	}
	
	public static DataFragment[] fragment(byte[] data, int payload_size, String[] names, Cipher[] encryptCiphers, Signature sig, PrivateKey privKey, SecureRandom sr) throws IOException, InvalidKeyException, SignatureException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
	
		int fragment_data_size = payload_size - Integer.BYTES;
		int n_fragments = getNfragments(data.length, payload_size);
		
		DataFragment[] fragments = new DataFragment[n_fragments];
				
		for(int i = 0; i < n_fragments; i++) {
			int start = i*fragment_data_size;
			int finish = start + Math.min(fragment_data_size, data.length - start);
			byte[] fragment_data = Arrays.copyOfRange(data, start, finish);
			
			int padding_len = fragment_data_size - fragment_data.length;
			byte[] padding = new byte[padding_len];
			sr.nextBytes(padding);
			
			ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
			DataOutputStream dataOut = new DataOutputStream(byteOut);
			
			dataOut.writeInt(padding_len);
			dataOut.write(padding, 0, padding_len);
			dataOut.write(fragment_data, 0, fragment_data.length);

			dataOut.flush();
			byteOut.flush();

			byte[] payload = Cryptography.encrypt(encryptCiphers[i], byteOut.toByteArray());

			dataOut.close();
			byteOut.close();

			byte[] signature = Cryptography.sign(sig, privKey, payload);

			fragments[i] = new DataFragment(names[i], fragment_data, padding, payload, signature);
		}
		
		return fragments;
	}
	
	public static byte[] defragment(DataFragment[] fragments) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IOException {
		byte[] data = new byte[0];
		
		for(DataFragment fragment : fragments) {
			data = ArrayUtil.concat(data, fragment.getData());
		}

		return data;
	}
	
}
