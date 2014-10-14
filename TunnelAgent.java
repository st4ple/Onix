import java.math.BigInteger;
import java.util.HashMap;
import java.util.Random;


public class TunnelAgent {
	/* 
	 * This method returns a HashMap containing a HashMap each 
	 * for a public/private RSA key pair. 
	 */
	public static HashMap<String, HashMap<String, BigInteger>> keyPair(){
		HashMap<String, HashMap<String, BigInteger>> keyValues = new HashMap<String, HashMap<String, BigInteger>>();

		Random rng = new Random(); 
		BigInteger p, q, n, v, k, d;            

		// assign prime values to p and q
		p = BigInteger.probablePrime(32, rng);
		q = BigInteger.probablePrime(32, rng);
		
		// compute n and v
		n = p.multiply(q);
		v = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

		// pick random number for k smaller than v until we find a number that is relative prime to v
		do {
			k = BigInteger.probablePrime(31, rng);
		} while (!(k.gcd(v)).equals(BigInteger.ONE));

		// calculate d for which is (d x k)%v = 1 ( = (k x d)%v ) (because 1 is the multiplicative identity)
		d = k.modInverse(v);
		
		// make a HashMap for both of the keys, containing k, n for the public key and d, n for the private key
		HashMap<String, BigInteger> publicKey = new HashMap<String, BigInteger>();
		publicKey.put("k", k);
		publicKey.put("n", n);
		HashMap<String, BigInteger> privateKey = new HashMap<String, BigInteger>();
		privateKey.put("d", d);
		privateKey.put("n", n);
		
		// store HashMaps of both keys in another HashMap to pass on the keys nicely to invokers of this method 
		keyValues.put("private", privateKey);
		keyValues.put("public", publicKey);

		return keyValues;
	}
	
	/* 
	 * This methods uses the given key on a given message, so it does 
	 * both encrypting and decrypting, depending on the parameter.
	 * It isn't responsible to ensure that the utilization of the given 
	 * key on the given message actually makes any sense!
	 */
	public static BigInteger crypt(BigInteger message, HashMap<String, BigInteger> key){
		if (key.containsKey("k")){
	    	return message.modPow(key.get("k"), key.get("n"));
		}
		else {
			 return message.modPow(key.get("d"), key.get("n"));
		}
	}
	
	
}
