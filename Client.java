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
		
		if(args.length > 0 ){
	    	message = args[0];
			if(args.length > 1 ){
				port = Integer.parseInt(args[1]);
				if(args.length > 2 ){
					IP = args[2];
				}
			}
		}
		
		// generate a key pair
		HashMap<String, HashMap<String, BigInteger>> keyValues = TunnelAgent.keyPair();

		HashMap<String, BigInteger> clientPrivateKey = keyValues.get("private");
		HashMap<String, BigInteger> clientPublicKey = keyValues.get("public");
				
		Socket socket = null;
		ObjectOutputStream objectOutputStream = null;
		ObjectInputStream objectInputStream = null;
		
        try {
        	socket = new Socket(IP, port);
        	System.out.println("Connected to server.");
			objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
			objectInputStream = new ObjectInputStream(socket.getInputStream());
			
        	// send own public key that server can authenticate my messages and encrypt his messages
			objectOutputStream.writeObject(clientPublicKey);
			
        	// receive server public key so I can authenticate the servers messages and encrypt my messages
        	@SuppressWarnings("unchecked")
			HashMap<String, BigInteger> serverPublicKey = (HashMap<String, BigInteger>) objectInputStream.readObject();
      
        	// prepare request message
        	String clearRequest = message;
			System.out.println("clearRequest = "+clearRequest);
        	BigInteger request = new BigInteger(clearRequest.getBytes());
        	
        	// encrypt message with my own private key (for server to verify that I'm the sender)
        	BigInteger oneSideEncryptedRequest = TunnelAgent.crypt(request, clientPrivateKey);
        	
        	// encrypt message with server public key (to verify that only server can decrypt with his private key)
        	BigInteger twoSideEncryptedRequest = TunnelAgent.crypt(oneSideEncryptedRequest, serverPublicKey);
        	
        	// send message
			objectOutputStream.writeObject(twoSideEncryptedRequest);
			System.out.println("encryptedRequest = "+twoSideEncryptedRequest);

        	// receive answer from server
        	BigInteger twoSideEncryptedAnswer = (BigInteger) objectInputStream.readObject();
			System.out.println("encryptedAnswer = "+twoSideEncryptedAnswer);

        	// decrypt message with my own private key (to read the message sent by server)
        	BigInteger oneSideEncryptedAnswer = TunnelAgent.crypt(twoSideEncryptedAnswer, clientPrivateKey);
        	
        	// decrypt message with server public key (to verify that messages was sent by server)
        	BigInteger answer = TunnelAgent.crypt(oneSideEncryptedAnswer, serverPublicKey);
        	
        	// handle the answer received from server
        	String clearAnswer = new String(answer.toByteArray());
        	System.out.println("clearAnswer = "+clearAnswer);
        	
        	// close connection
        	socket.close();
        	
        	System.out.println("Disconnected from server.");
        	
        } catch (IOException | ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}   
        
	}

}
