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
		
        for (int i=0; i<args.length; i++){
            if (args[i].equals("-v")){
				verbose = true;
            }
            if (args[i].equals("-p") && args.length > (i+1)){
                    port = Integer.parseInt(args[i+1]);
            }
        }
		
		HashMap<String, HashMap<String, BigInteger>> keyValues = TunnelAgent.createPairOfKeys(verbose);
		HashMap<String, BigInteger> serverPrivateKey = keyValues.get("private");
		HashMap<String, BigInteger> serverPublicKey = keyValues.get("public");
		
		ObjectOutputStream objectOutputStream = null;
		ObjectInputStream objectInputStream = null;
		ServerSocket serverSocket = null;
		
		try {
			serverSocket = new ServerSocket(port);
	    
	    	while(true){
                System.out.println("Listening on socket on port "+port+".");
	    		// Open socket for new Client that connects
	    		Socket ms = serverSocket.accept();
                if (verbose) System.out.println("******** TUNNEL-START *********");
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
				
                // receive encrypted request from client
	        	BigInteger twoSideEncryptedRequest = (BigInteger) objectInputStream.readObject();
				if (verbose) System.out.println("Encrypted request: "+twoSideEncryptedRequest);

	        	// decrypt message with my own private key (to read the actual message sent by the client)
	        	BigInteger oneSideEncryptedRequest = TunnelAgent.crypt(twoSideEncryptedRequest, serverPrivateKey);
				if (verbose) System.out.println("Decrypt request with Server Private Key.");

				// decrypt message with clients public key (to verify they are the sender)
	        	BigInteger request = TunnelAgent.crypt(oneSideEncryptedRequest, clientPublicKey);
				if (verbose) System.out.println("Decrypt request with Client Public Key.");

	        	// handle the request
	        	String clearRequest = new String(TunnelAgent.bigIntegerToString(request));
				System.out.println("Clear request: "+clearRequest);

				// prepare answer
				String clearAnswer = clearRequest.toUpperCase();
				BigInteger answer = TunnelAgent.stringToBigInteger(clearAnswer);
				System.out.println("Clear answer: "+clearAnswer);
                if (verbose) System.out.println("Coded answer message is smaller than n: " + (serverPublicKey.get("n").compareTo(answer)==1));
                
                if (serverPublicKey.get("n").compareTo(answer)==1){

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
                    if (verbose) System.out.println("********* TUNNEL-END **********");
                }
                else{
                    if (verbose) System.out.println("Oops, something went wrong. Retrying.");
                    if (verbose) System.out.println("******** TUNNEL-ABORT *********");
                }
                ms.close();
                    

	    	}
		
		}
		catch (IOException e) { System.out.println("IO"); } 
        catch (ClassNotFoundException e) { System.out.println("Class"); }
	}
		
}


