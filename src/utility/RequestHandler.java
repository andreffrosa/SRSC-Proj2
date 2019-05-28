package utility;

public interface RequestHandler<K,T> {
	T execute(K arg) throws Exception;
}