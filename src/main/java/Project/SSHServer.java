package Project;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;

public class SSHServer {
    private static final int PORT = 2222;
    private ServerSocket serverSocket;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private KeyPairGenerator keyPairGen;
    private KeyPair keyPair;
    private KeyAgreement keyAgreement;
    private KeyPair dhKeyPair;
    private DHParameterSpec dhParams;

    public static void main(String[] args) {

    }

    public void start() {
        try{
            // gjenero Rsa çelesat per autentikim te serverit
            keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            keyPair = keyPairGen.generateKeyPair();
            privateKey  = keyPair.getPrivate();
            publicKey = keyPair.getPublic();

            //gjenero D.H. parametrat per shkembimin e çelësave
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(2048);
            AlgorithmParameters params = paramGen.generateParameters();
            dhParams = params.getParameterSpec(DHParameterSpec.class);

            serverSocket = new ServerSocket(PORT);
            System.out.println("Server starting up...");
            System.out.println("Awaiting client connections...");

            while (true){
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected! Initiating handshake...");

                //...
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
