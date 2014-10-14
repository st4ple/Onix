
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
		
		if(args.length > 0 ){
	    	port = Integer.parseInt(args[0]);
		}
		
		HashMap<String, HashMap<String, BigInteger>> keyValues = TunnelAgent.createPairOfKeys();

		HashMap<String, BigInteger> serverPrivateKey = keyValues.get("private");
		HashMap<String, BigInteger> serverPublicKey = keyValues.get("public");
		
		ObjectOutputStream objectOutputStream = null;
		ObjectInputStream objectInputStream = null;
		ServerSocket serverSocket = null;
		
		try {
			serverSocket = new ServerSocket(port);
			System.out.println("Listening on socket on port "+port+".");
	    
	    	while(true){
	    		// Open socket for new Client that connects
	    		Socket ms = serverSocket.accept();
				System.out.println("A client has connected.");
			
				objectOutputStream = new ObjectOutputStream(ms.getOutputStream());
				objectInputStream = new ObjectInputStream(ms.getInputStream());
				
	        	// receive clients public key so I can authenticate their messages and encrypt my messages
	        	@SuppressWarnings("unchecked")
				HashMap<String, BigInteger> clientPublicKey = (HashMap<String, BigInteger>) objectInputStream.readObject();

	        	// send own public key that clients can authenticate my messages and encrypt their messages
				objectOutputStream.writeObject(serverPublicKey);
				
	        	BigInteger twoSideEncryptedRequest = (BigInteger) objectInputStream.readObject();
				System.out.println("encryptedRequest = "+twoSideEncryptedRequest);

	        	// decrypt message with my own private key (to read the actual message sent by the client)
	        	BigInteger oneSideEncryptedRequest = TunnelAgent.crypt(twoSideEncryptedRequest, serverPrivateKey);

				// decrypt message with clients public key (to verify they are the sender)
	        	BigInteger request = TunnelAgent.crypt(oneSideEncryptedRequest, clientPublicKey);

	        	// handle the request
	        	String clearRequest = new String(request.toByteArray());
				System.out.println("clearRequest = "+clearRequest);

				// prepare answer
				String clearAnswer = clearRequest.toUpperCase();
				BigInteger answer = new BigInteger(clearAnswer.getBytes());
				System.out.println("clearAnswer = "+clearAnswer);

				// encrypt message with own private key (to verify to client that I'm the sender)
	        	BigInteger oneSideEncryptedAnswer = TunnelAgent.crypt(answer, serverPrivateKey);

				// encrypt message with clients public key (to verify that only the client can decrypt with his private key)
	        	BigInteger twoSideEncryptedAnswer = TunnelAgent.crypt(oneSideEncryptedAnswer, clientPublicKey);

				// send encrypted answer
				objectOutputStream.writeObject(twoSideEncryptedAnswer);
				System.out.println("encryptedAnswer = "+twoSideEncryptedAnswer);

				// close connection to client
				ms.close();
				
				System.out.println("Connection to client closed.");	
	    	}
		
		}
		catch (IOException e) {} catch (ClassNotFoundException e) {}
      
	}
		
}


