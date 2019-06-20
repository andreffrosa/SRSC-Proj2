package fServer.authServer.models;

public class EnvelopedToken {

	private byte[] token;
	private byte[] server_answer;
	
	public EnvelopedToken(byte[] token, byte[] server_answer) {
		this.token = token;
		this.server_answer = server_answer;
	}

	public byte[] getToken() {
		return token;
	}

	public byte[] getServer_answer() {
		return server_answer;
	}
	
}
