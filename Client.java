import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.HashMap;

public class Client {

    public static void main(String[] args) {
	   	
        String host = "localhost";
        int port = 4444;
        String message = "test";
        boolean verbose = false;

        for (int i=0; i<args.length; i++){
            if (args[i].equals("-v")){
                verbose = true;
            }
            if (args[i].equals("-h") && args.length > (i+1)){
                host = args[i+1];
            }
            if (args[i].equals("-p") && args.length > (i+1)){
                port = Integer.parseInt(args[i+1]);
            }
            if (args[i].equals("-m") && args.length > (i+1)){
                message = args[i+1];
            }
            if (args[i].equals("-h")){
                System.out.println("Usage: java Client (-m <message>) (-h <host_address>) (-p <port_number>) (-v)");
                System.out.println("args: -m <message>      => the message that should be sent through the  RSA tunnel");
                System.out.println("                           (currently only short messages of few characters work properly");
                System.out.println("      -h <host_address> => the address of the server to connect to");
                System.out.println("      -p <port_number>  => the port number of the server to connect to");
                System.out.println("      -v                => to receive verbose output of events when running the client");
                System.exit(1);
            }
        }

        // generate a key pair
        HashMap<String, HashMap<String, BigInteger>> keyValues = OnixHelper.createPairOfKeys(verbose);
        HashMap<String, BigInteger> clientPrivateKey = keyValues.get("private");
        HashMap<String, BigInteger> clientPublicKey = keyValues.get("public");

        if (verbose) System.out.println("Attempting to connect to server.");

        Socket socket = null;
        ObjectOutputStream objectOutputStream = null;
        ObjectInputStream objectInputStream = null;

        try {
            socket = new Socket(host, port);
            if (verbose) System.out.println("******** TUNNEL-START *********");
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
            BigInteger request = OnixHelper.stringToBigInteger(clearRequest);

            // encrypt message with my own private key (for server to verify that I'm the sender)
            BigInteger oneSideEncryptedRequest = OnixHelper.crypt(request, clientPrivateKey);
            if (verbose) System.out.println("Encrypt request with Client Private Key.");

            // encrypt message with server public key (to verify that only server can decrypt with his private key)
            BigInteger twoSideEncryptedRequest = OnixHelper.crypt(oneSideEncryptedRequest, serverPublicKey);
            if (verbose) System.out.println("Encrypt request with Server Public Key.");

            // send encrypted request
            objectOutputStream.writeObject(twoSideEncryptedRequest);
            if (verbose) System.out.println("Encrypted request sent: "+twoSideEncryptedRequest);

            // receive encrypted answer from server
            BigInteger twoSideEncryptedAnswer = (BigInteger) objectInputStream.readObject();
            if (verbose) System.out.println("Encrypted answer received: "+twoSideEncryptedAnswer);

            if (verbose) System.out.println("Coded answer message is smaller than n: " + (serverPublicKey.get("n").compareTo(twoSideEncryptedAnswer)==1));

            // decrypt message with my own private key (to read the message sent by server)
            BigInteger oneSideEncryptedAnswer = OnixHelper.crypt(twoSideEncryptedAnswer, clientPrivateKey);
            if (verbose) System.out.println("Decrypt answer with Client Private Key.");

            // decrypt message with server public key (to verify that messages was sent by server)
            BigInteger answer = OnixHelper.crypt(oneSideEncryptedAnswer, serverPublicKey);
            if (verbose) System.out.println("Decrypt answer with Server Public Key.");

            // handle the answer received from server
            String clearAnswer = new String(OnixHelper.bigIntegerToString(answer));
            System.out.println("Clear answer: "+clearAnswer);

            // close connection
            socket.close();

            if (verbose) System.out.println("Disconnected from server.");
            if (verbose) System.out.println("********* TUNNEL-END **********");

        } catch (IOException i){
            // this exception happens in rare cases when the coded message (in BigInteger) is > n
            // in such cases, a new key is generated and the tunnel procedure is restarted
            if (verbose) System.out.println("******** TUNNEL-ABORT *********");
            main(args);
        } catch (ClassNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }   
        
	}

}
