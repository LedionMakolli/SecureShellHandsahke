package Project;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.swing.plaf.TableHeaderUI;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SSHServer {
    private static final int PORT = 22226;
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

                new ClinetHandler(clientSocket).start();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private class ClinetHandler extends Thread {
        private Socket clientSocket;
        private ObjectOutput out;
        private ObjectInputStream in;

        public ClinetHandler(Socket socket){
            this.clientSocket = socket;
        }

        public  void run(){
            try {
                out = new ObjectOutputStream(clientSocket.getOutputStream());
                in = new ObjectInputStream(clientSocket.getInputStream());

                // dergo indetifikimin e serverit
                sendIdentification();

                // performo kembimin e qelesave
                byte[] sharedSecret = performKeyExchange();

                // autorizo serverin per klient
                authenticateServer(sharedSecret);

                // gjenro seesion qelesat
                generateSessionKeys(sharedSecret);

                System.out.println("Handshake successfull. Procceding to establish secure channel...");

            } catch (Exception e) {
                System.err.println("Error handling client: " + e.getMessage());
            }finally {
                try{
                    clientSocket.close();
                }catch (IOException e){
                    e.printStackTrace();
                }
        }
}





 private void sendIdentification() throws IOException {
            Map<String, Object> identification = new HashMap<>();
            identification.put("server_id", "SSH_Server_1.0");

            Map<String, List<String>> algorithms = new HashMap<>();
            algorithms.put("kex", Arrays.asList("diffie-hellman-group14-sha256"));// algoritmi per shkembim celesave
            algorithms.put("hostkey", Arrays.asList("ssh-rsa")); // algoritmi per nenshkrimin e celesit te serverit
            algorithms.put("encryption", Arrays.asList("aes256-ctr")); // algoritmi per enkriptim
            algorithms.put("mac", Arrays.asList("hmac-sha256")); // algoritmi per kodin e verifikimit te mesazhit

            identification.put("supported_algorithms", algorithms);

            out.writeObject(identification);
            out.flush();
        }

        private byte[] performKeyExchange() throws Exception {
            // Gjeneron cift celesash per algoritmin Diffie-Hellman
            KeyPairGenerator dhKpairGen = KeyPairGenerator.getInstance("DH");
            dhKpairGen.initialize(dhParams);
            dhKeyPair = dhKpairGen.generateKeyPair();

            // Dergon celesin publik DH te serverit
            out.writeObject(dhKeyPair.getPublic());
            out.flush();

            // Pranon celesin publik DH te klientit
            PublicKey clientDhPublicKey = (PublicKey) in.readObject();

            // key agreement
            keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(dhKeyPair.getPrivate());
            keyAgreement.doPhase(clientDhPublicKey, true);
            // Gjeneron sekretin e perbashket
            byte[] sharedSecret = keyAgreement.generateSecret();
            return sharedSecret;
        }


        private void authenticateServer(byte[] sharedSecret) throws Exception {
            // Nenshkruan sekretin e perbashket me celesin privat te serverit
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(sharedSecret);
            byte[] signed = signature.sign();

            // Dergon celesin publik te serverit dhe nenshkrimin
            Map<String, Object> authData = new HashMap<>();
            authData.put("public_key", publicKey);
            authData.put("signature", signed);

            out.writeObject(authData);
            out.flush();
        }

        private void generateSessionKeys(byte[] sharedSecret) throws Exception {
            // Derivon celesat e sesionit duke perdorur HKDF mbi sekretin e perbashket
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] prk = digest.digest(sharedSecret);

            // Derivon celesin e enkriptimit
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

            // Dergon konfirmim tek klienti se celesat e sesionit u krijuan me sukses
            out.writeObject("Session keys established");
            out.flush();
        }
    }
}
