import java.math.BigInteger;
import java.util.HashMap;
import java.util.Random;


public class OnixHelper {
    /* 
     * This method returns a HashMap containing a HashMap each 
     * for a public/private RSA key pair. 
     */
    public static HashMap<String, HashMap<String, BigInteger>> createPairOfKeys(boolean verbose){
        HashMap<String, HashMap<String, BigInteger>> keyValues = new HashMap<String, HashMap<String, BigInteger>>();

        Random rng = new Random(); 
        BigInteger p, q, n, v, e, d;            

        if (verbose) System.out.println("********** RSA-START **********");

        // assign prime values to p and q => probablePrime(64, rng) returns 64 bit BigIntegers that are most probably prime 
        // probability that the returned value is not prime is 2^-100
        p = BigInteger.probablePrime(64, rng);
        if (verbose) System.out.println("p = "+p);
        q = BigInteger.probablePrime(64, rng);
        if (verbose) System.out.println("q = "+q);

        // compute n and v
        n = p.multiply(q); //equivalent to: n=p*q
        if (verbose) System.out.println("n = "+n);
        v = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE)); //equivalent to: v = (p-1)*(q-1)
        if (verbose) System.out.println("v = "+v);

        // pick random number for e smaller than v until we find a number that is relative prime to v
        do {
            e = BigInteger.probablePrime(8, rng);
        } while (!(e.gcd(v)).equals(BigInteger.ONE)); //equivalent to: pick e, e prime, gcd(e,v)=1
        if (verbose) System.out.println("e = "+e);

        // calculate d for which is (d*e)%v = 1 ( = (e*d)%v ) (because 1 is the multiplicative identity for the set of the real numbers)
        d = e.modInverse(v); //equivalent to: pick d, (d*e)modulo(v)=1
        if (verbose) System.out.println("d = "+d);

        // verify that keys are correct by printing out some "test values"
        if (verbose) System.out.println("gcd(e,v) = "+e.gcd(v));
        if (verbose) System.out.println("(d*e)%v = "+(d.multiply(e)).mod(v));

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

        if (verbose){
            System.out.println("Private Key: "+privateKey.toString());
            System.out.println("Public Key: "+publicKey.toString());
            System.out.println("*********** RSA-END ***********");
        }
        return keyValues;
    }
     
    public static HashMap<String, HashMap<String, BigInteger>> createPairOfKeys(){
        return createPairOfKeys(false);
    }

    /* 
     * This method uses the given key on a given message, so it does 
     * both encrypting and decrypting, depending on the parameter.
     * It isn't responsible to ensure that the utilization of the given 
     * key on the given message actually makes any sense!
     */
    public static BigInteger crypt(BigInteger message, HashMap<String, BigInteger> key){
        // check if the key contains a value for "e". in this case, use the public key
        if (key.containsKey("e")){
            return message.modPow(key.get("e"), key.get("n")); //equivalent to: (message^e)modulo(n)
        }
        // if the key does not contain a value "e", use the private key
        else {
            return message.modPow(key.get("d"), key.get("n")); //equivalent to: (message^d)modulo(n)
        }
    }
    
    /*
     * This method encodes a String to BigInteger format. 
     * It assigns a numerical BigInteger value to a String of characters.
     * Use this method to prepare a String for encryption.
     */
    public static BigInteger stringToBigInteger(String str){
        byte[] strBytes = str.getBytes();
        return new BigInteger(strBytes);
    }

    /*
     * This method decodes a number in BigInteger format back to a String.
     * It assigns a String of characters to numerical BigInteger value.
     * Use this method after decrypting a message in BigInteger format to
     * make it readable by humans.
     */
    public static String bigIntegerToString(BigInteger bigInt){
        return new String(bigInt.toByteArray());
    }


}
