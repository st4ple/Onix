import java.math.BigInteger;
import java.util.HashMap;
import java.util.Random;


public class TunnelAgent {
	/* 
	 * This method returns a HashMap containing a HashMap each 
	 * for a public/private RSA key pair. 
	 */
	public static HashMap<String, HashMap<String, BigInteger>> createPairOfKeys(boolean verbose){
		HashMap<String, HashMap<String, BigInteger>> keyValues = new HashMap<String, HashMap<String, BigInteger>>();

		Random rng = new Random(); 
		BigInteger p, q, n, v, e, d;            

        if (verbose) System.out.println("**********RSA-START**********");
        
		// assign prime values to p and q
		p = BigInteger.probablePrime(64, rng);
        if (verbose) System.out.println("p = "+p);
		q = BigInteger.probablePrime(64, rng);
        if (verbose) System.out.println("q = "+q);
		
		// compute n and v
		n = p.multiply(q);
        if (verbose) System.out.println("n = "+n);
		v = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        if (verbose) System.out.println("v = "+v);
        
		// pick random number for e smaller than v until we find a number that is relative prime to v
		do {
			e = BigInteger.probablePrime(8, rng);
		} while (!(e.gcd(v)).equals(BigInteger.ONE));
        if (verbose) System.out.println("e = "+e);

		// calculate d for which is (d x e)%v = 1 ( = (e x d)%v ) (because 1 is the multiplicative identity)
		d = e.modInverse(v);
        if (verbose) System.out.println("d = "+d);
        
        // verify that keys are correct
        if (verbose) System.out.println("gcd(e,v) = "+e.gcd(v));
        if (verbose) System.out.println("(d*e)%v = "+(d.multiply(e)).mod(v));
        if (verbose) System.out.println("e < v: " + (v.compareTo(e)==1));
        
        // n = new BigInteger("3233");
        // e = new BigInteger("1013");
        // d = new BigInteger("77");
		
		// make a HashMap for both of the keys, containing e, n for the public key and d, n for the private key
		HashMap<String, BigInteger> publicKey = new HashMap<String, BigInteger>();
		publicKey.put("e", e);
		publicKey.put("n", n);
		HashMap<String, BigInteger> privateKey = new HashMap<String, BigInteger>();
		privateKey.put("d", d);
		privateKey.put("n", n);
		
		// store HashMaps of both keys in another HashMap to pass on the keys nicely to invokers of this method 
		keyValues.put("private", privateKey);
		keyValues.put("public", publicKey);
        
        if (verbose) System.out.println("***********RSA-END***********");

		return keyValues;
	}
    
    public static HashMap<String, HashMap<String, BigInteger>> createPairOfKeys(){
        return createPairOfKeys(false);
    }
	
	/* 
	 * This methods uses the given key on a given message, so it does 
	 * both encrypting and decrypting, depending on the parameter.
	 * It isn't responsible to ensure that the utilization of the given 
	 * key on the given message actually makes any sense!
	 */
	public static BigInteger crypt(BigInteger message, HashMap<String, BigInteger> key, boolean verbose){
        if (verbose) System.out.println("**********CRYPT-START**********");
        if (key.containsKey("e")){
            if (verbose) System.out.println("***********CRYPT-END***********");
	    	return message.modPow(key.get("e"), key.get("n"));
		}
		else {
            if (verbose) System.out.println("***********CRYPT-END***********");
            return message.modPow(key.get("d"), key.get("n"));
		}
	}
    
    public static BigInteger crypt(BigInteger message, HashMap<String, BigInteger> key){
		return crypt(message, key, false);
	}
    
     
    public static BigInteger stringToBigInteger(String str){
        /* BigInteger bigInt = new BigInteger("0");
        BigInteger constant = new BigInteger("1000");
        String tmp;
        for (char c : str.toCharArray()){
            tmp = ((int)c).toString();
            bigInt.add(BigInteger(tmp));
            bigInt.mulitply(constant);
        }
        bigInt.divide(constant);
        return bigInt; */
        byte[] strBytes = str.getBytes();
        return new BigInteger(strBytes);
    }
    
    public static String bigIntegerToString(BigInteger bigInt){
        /* BigInteger constant = new BigInteger("1000");
        String string "";
        while (bigInt.compareTo(BigInteger.ONE)==1){
            
        return c.toString(); */
        return new String(bigInt.toByteArray());
    }
    
    
}
