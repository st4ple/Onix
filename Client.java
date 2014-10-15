import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.HashMap;

public class Client {

	public static void main(String[] args) {
	   	
		String IP = "localhost";
		int port = 4444;
		String message = "This is just a test message!";
		boolean verbose = false;
		int offset = 0;
		
		if(args.length > 0 ){
			if (args[0].equals("-v")){
				verbose = true;
				offset = 1;
			}
			if(args.length > (0+offset) ){
				message = args[0+offset];
				if(args.length > (1+offset) ){
					port = Integer.parseInt(args[1+offset]);
					if(args.length > (2+offset) ){
						IP = args[2+offset];
					}
				}
			}
		}
		System.out.println("--------------------------------");
		
		// generate a key pair
		HashMap<String, HashMap<String, BigInteger>> keyValues = TunnelAgent.createPairOfKeys();
		HashMap<String, BigInteger> clientPrivateKey = keyValues.get("private");
		HashMap<String, BigInteger> clientPublicKey = keyValues.get("public");
		
		if (verbose){
			System.out.println("Client Private Key created: "+clientPrivateKey.toString());
			System.out.println("Client Public Key created: "+clientPublicKey.toString());
		}
				
		Socket socket = null;
		ObjectOutputStream objectOutputStream = null;
		ObjectInputStream objectInputStream = null;
		
        try {
        	socket = new Socket(IP, port);
        	if (verbose) System.out.println("Connected to server.");
			objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
			objectInputStream = new ObjectInputStream(socket.getInputStream());
			
        	// send own public key that server can authenticate my messages and encrypt his messages
			objectOutputStream.writeObject(clientPublicKey);
			if (verbose) System.out.println("Client Public Key sent to server.");
			
        	// receive server public key so I can authenticate the servers messages and encrypt my messages
        	@SuppressWarnings("unchecked")
			HashMap<String, BigInteger> serverPublicKey = (HashMap<String, BigInteger>) objectInputStream.readObject();
        	if (verbose) System.out.println("Server Public Key received: "+serverPublicKey.toString());
      
        	// prepare request message
        	String clearRequest = message;
			System.out.println("Clear request: "+clearRequest);
        	BigInteger request = new BigInteger(clearRequest.getBytes());
        	
        	// encrypt message with my own private key (for server to verify that I'm the sender)
        	BigInteger oneSideEncryptedRequest = TunnelAgent.crypt(request, clientPrivateKey);
			if (verbose) System.out.println("Encrypt request with Client Private Key.");
        	
        	// encrypt message with server public key (to verify that only server can decrypt with his private key)
        	BigInteger twoSideEncryptedRequest = TunnelAgent.crypt(oneSideEncryptedRequest, serverPublicKey);
			if (verbose) System.out.println("Encrypt request with Server Public Key.");
        	
        	// send message
			objectOutputStream.writeObject(twoSideEncryptedRequest);
			if (verbose) System.out.println("Encrypted request sent: "+twoSideEncryptedRequest);

        	// receive answer from server
        	BigInteger twoSideEncryptedAnswer = (BigInteger) objectInputStream.readObject();
			if (verbose) System.out.println("Encrypted answer received: "+twoSideEncryptedAnswer);

        	// decrypt message with my own private key (to read the message sent by server)
        	BigInteger oneSideEncryptedAnswer = TunnelAgent.crypt(twoSideEncryptedAnswer, clientPrivateKey);
			if (verbose) System.out.println("Decrypt answer with Client Private Key.");
        	
        	// decrypt message with server public key (to verify that messages was sent by server)
        	BigInteger answer = TunnelAgent.crypt(oneSideEncryptedAnswer, serverPublicKey);
			if (verbose) System.out.println("Decrypt request with Server Public Key.");
        	
        	// handle the answer received from server
        	String clearAnswer = new String(answer.toByteArray());
        	System.out.println("Clear answer: "+clearAnswer);
        	
        	// close connection
        	socket.close();
        	
        	if (verbose) System.out.println("Disconnected from server.");
    		System.out.println("--------------------------------");

        } catch (IOException | ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}   
        
	}

}
