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


        private void authenticateServer(byte[] sharedSecret) throws Exception {
            // Sign the shared secret
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(sharedSecret);
            byte[] signed = signature.sign();

            // Send server's public key and signature
            Map<String, Object> authData = new HashMap<>();
            authData.put("public_key", publicKey);
            authData.put("signature", signed);

            out.writeObject(authData);
            out.flush();
        }

        private void generateSessionKeys(byte[] sharedSecret) throws Exception {
            // Derive session keys using HKDF
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] prk = digest.digest(sharedSecret);

            // Derive encryption key (simplified)
            byte[] info = "session keys".getBytes();
            byte[] okm = new byte[32];

            byte[] t = new byte[0];
            int remaining = okm.length;
            int offset = 0;

            for (int i = 1; remaining > 0; i++) {
                digest.reset();
                digest.update(t);
                digest.update(info);
                digest.update((byte) i);
                t = digest.digest();

                int toCopy = Math.min(t.length, remaining);
                System.arraycopy(t, 0, okm, offset, toCopy);
                offset += toCopy;
                remaining -= toCopy;
            }

            // Send confirmation to client
            out.writeObject("Session keys established");
            out.flush();
        }
    }
}
