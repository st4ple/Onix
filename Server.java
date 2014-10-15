import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;

public class Server {

	public static void main(String[] args){		

		int port = 4444;
		boolean verbose = false;
		int offset = 0;
		
		if(args.length > 0 ){
			if (args[0].equals("-v")){
				verbose = true;
				offset = 1;
			}
			if(args.length > (0+offset) ){
				port = Integer.parseInt(args[0+offset]);
			}
		}
		
		HashMap<String, HashMap<String, BigInteger>> keyValues = TunnelAgent.createPairOfKeys();
		HashMap<String, BigInteger> serverPrivateKey = keyValues.get("private");
		HashMap<String, BigInteger> serverPublicKey = keyValues.get("public");
		
		if (verbose){
			System.out.println("Server Private Key created: "+serverPrivateKey.toString());
			System.out.println("Server Public Key created: "+serverPublicKey.toString());
		}
		
		ObjectOutputStream objectOutputStream = null;
		ObjectInputStream objectInputStream = null;
		ServerSocket serverSocket = null;
		
		try {
			serverSocket = new ServerSocket(port);
			System.out.println("Listening on socket on port "+port+".");
	    
	    	while(true){
	    		System.out.println("--------------------------------");
	    		// Open socket for new Client that connects
	    		Socket ms = serverSocket.accept();
	        	if (verbose) System.out.println("A client has connected.");
			
				objectOutputStream = new ObjectOutputStream(ms.getOutputStream());
				objectInputStream = new ObjectInputStream(ms.getInputStream());
				
	        	// receive clients public key so I can authenticate their messages and encrypt my messages
	        	@SuppressWarnings("unchecked")
				HashMap<String, BigInteger> clientPublicKey = (HashMap<String, BigInteger>) objectInputStream.readObject();
	        	if (verbose) System.out.println("Client Public Key received: "+clientPublicKey.toString());

	        	// send own public key that clients can authenticate my messages and encrypt their messages
				objectOutputStream.writeObject(serverPublicKey);
				if (verbose) System.out.println("Server Public Key sent to client.");
				
	        	BigInteger twoSideEncryptedRequest = (BigInteger) objectInputStream.readObject();
				System.out.println("Encrypted request: "+twoSideEncryptedRequest);

	        	// decrypt message with my own private key (to read the actual message sent by the client)
	        	BigInteger oneSideEncryptedRequest = TunnelAgent.crypt(twoSideEncryptedRequest, serverPrivateKey);
				if (verbose) System.out.println("Decrypt request with Server Private Key.");

				// decrypt message with clients public key (to verify they are the sender)
	        	BigInteger request = TunnelAgent.crypt(oneSideEncryptedRequest, clientPublicKey);
				if (verbose) System.out.println("Decrypt request with Client Public Key.");

	        	// handle the request
	        	String clearRequest = new String(request.toByteArray());
				System.out.println("Clear request: "+clearRequest);

				// prepare answer
				String clearAnswer = clearRequest.toUpperCase();
				BigInteger answer = new BigInteger(clearAnswer.getBytes());
				System.out.println("Clear answer: "+clearAnswer);

				// encrypt message with own private key (to verify to client that I'm the sender)
	        	BigInteger oneSideEncryptedAnswer = TunnelAgent.crypt(answer, serverPrivateKey);
				if (verbose) System.out.println("Encrypt answer with Server Private Key.");

				// encrypt message with clients public key (to verify that only the client can decrypt with his private key)
	        	BigInteger twoSideEncryptedAnswer = TunnelAgent.crypt(oneSideEncryptedAnswer, clientPublicKey);
				if (verbose) System.out.println("Encrypt answer with Client Public Key.");

				// send encrypted answer
				objectOutputStream.writeObject(twoSideEncryptedAnswer);
				if (verbose) System.out.println("Encrypted answer: "+twoSideEncryptedAnswer);

				// close connection to client
				ms.close();
				
				if (verbose) System.out.println("Connection to client closed.");	
	    	}
		
		}
		catch (IOException e) {} catch (ClassNotFoundException e) {}
      
	}
		
}


