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





 private void sendIdentification() throws IOException {
            Map<String, Object> identification = new HashMap<>();
            identification.put("server_id", "SSH_Server_1.0");

            Map<String, List<String>> algorithms = new HashMap<>();
            algorithms.put("kex", Arrays.asList("diffie-hellman-group14-sha256"));
            algorithms.put("hostkey", Arrays.asList("ssh-rsa"));
            algorithms.put("encryption", Arrays.asList("aes256-ctr"));
            algorithms.put("mac", Arrays.asList("hmac-sha256"));

            identification.put("supported_algorithms", algorithms);

            out.writeObject(identification);
            out.flush();
        }

        private byte[] performKeyExchange() throws Exception {
            // Generate DH key pair
            KeyPairGenerator dhKpairGen = KeyPairGenerator.getInstance("DH");
            dhKpairGen.initialize(dhParams);
            dhKeyPair = dhKpairGen.generateKeyPair();

            // Send server's DH public key
            out.writeObject(dhKeyPair.getPublic());
            out.flush();

            // Receive client's DH public key
            PublicKey clientDhPublicKey = (PublicKey) in.readObject();

            // Perform key agreement
            keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(dhKeyPair.getPrivate());
            keyAgreement.doPhase(clientDhPublicKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();
            return sharedSecret;
        }
