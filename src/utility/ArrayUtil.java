package utility;

public class ArrayUtil {

	/**
	 * Concatenates two byte arrays
	 * @param a first array
	 * @param b second array
	 * @return concatenation result
	 */
	public static byte[] concat (byte[] a, byte[] b){
		if (a == null) return b;
	    if (b == null) return a;
	    byte[] r = new byte[a.length+b.length];
	    System.arraycopy(a, 0, r, 0, a.length);
	    System.arraycopy(b, 0, r, a.length, b.length);
	    return r;
	}
	
	/*public static <T> String toString(T[] array) {
		String s = ""
	}*/
	
	public static String[] unparseString(String array) {
		if(array == null)
			return null;

		String aux = array.substring(1, array.length()-1);
		String s[] = aux.split(",");

		String[] result = new String[s.length];

		for(int i = 0; i < s.length; i++) {
			result[i] = s[i].trim();
		}

		return result;
	}
	
	public static byte[] unparse(String array) {
		if(array == null)
			return null;

		String aux = array.substring(1, array.length()-1);
		String s[] = aux.split(",");

		byte[] result = new byte[s.length];

		for(int i = 0; i < s.length; i++) {
			result[i] = (byte) Integer.parseInt(s[i].trim().replace("0x", ""), 16);
		}

		return result;
	}
	
	public static byte[] longToBytes(long l) {
	    byte[] result = new byte[Long.BYTES];
	    for (int i = Long.BYTES-1; i >= 0; i--) {
	        result[i] = (byte)(l & 0xFF);
	        l >>= Long.BYTES;
	    }
	    return result;
	}

	public static long bytesToLong(byte[] b) {
	    long result = 0;
	    for (int i = 0; i < Long.BYTES; i++) {
	        result <<= Long.BYTES;
	        result |= (b[i] & 0xFF);
	    }
	    return result;
	}
	
}
