package utility;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class mySSLSocket extends SSLSocket {
	
	private SSLSocket socket;
	
	public mySSLSocket(SSLSocketFactory sf) throws UnknownHostException, IOException {
		super();
		this.socket = (SSLSocket) sf.createSocket(InetAddress.getByName("localhost"), 8888);
		this.socket.setEnabledCipherSuites(new String[] {"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"});
		this.socket.setEnabledProtocols(new String[] {"TLSv1.2"});
		this.socket.setNeedClientAuth(true);
		this.socket.startHandshake();
	}

	@Override
	public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
		socket.addHandshakeCompletedListener(listener);
	}

	@Override
	public boolean getEnableSessionCreation() {
		return socket.getEnableSessionCreation();
	}

	@Override
	public String[] getEnabledCipherSuites() {
		return socket.getEnabledCipherSuites();
	}

	@Override
	public String[] getEnabledProtocols() {
		return socket.getEnabledProtocols();
	}

	@Override
	public boolean getNeedClientAuth() {
		return socket.getNeedClientAuth();
	}

	@Override
	public SSLSession getSession() {
		return socket.getSession();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return socket.getSupportedCipherSuites();
	}

	@Override
	public String[] getSupportedProtocols() {
		return socket.getSupportedProtocols();
	}

	@Override
	public boolean getUseClientMode() {
		return socket.getUseClientMode();
	}

	@Override
	public boolean getWantClientAuth() {
		return socket.getWantClientAuth();
	}

	@Override
	public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
		socket.removeHandshakeCompletedListener(listener);
	}

	@Override
	public void setEnableSessionCreation(boolean flag) {
		socket.setEnableSessionCreation(flag);

	}

	@Override
	public void setEnabledCipherSuites(String[] suites) {
		socket.setEnabledCipherSuites(suites);
	}

	@Override
	public void setEnabledProtocols(String[] protocols) {
		socket.setEnabledProtocols(protocols);
	}

	@Override
	public void setNeedClientAuth(boolean need) {
		socket.setNeedClientAuth(need);

	}

	@Override
	public void setUseClientMode(boolean mode) {
		socket.setUseClientMode(mode);
	}

	@Override
	public void setWantClientAuth(boolean want) {
		socket.setWantClientAuth(want);
	}

	@Override
	public void startHandshake() throws IOException {
		System.out.println("Starting handshake!");
		socket.startHandshake();
	}

}
