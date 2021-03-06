import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Created by Nathaniel on 20/1/2015.
 */
public class Server {

    public static void main(String[] args) throws Exception {
        int portNumber = 9000;

        try (
                ServerSocket serverSocket = new ServerSocket(portNumber);
                Socket clientSocket = serverSocket.accept();
                PrintWriter out =
                        new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(clientSocket.getInputStream()));
        ) {


            String inputLine, outputLine;

            // Initiate conversation with client
            ServerSecureProtocol serverSecureProtocol = new ServerSecureProtocol();
            outputLine = serverSecureProtocol.processInput(null);
            System.out.println("Server: " + portNumber + " " + outputLine);
            out.println(outputLine);

            while ((inputLine = in.readLine()) != null) {
                System.out.println("Client: " + inputLine);
                outputLine = serverSecureProtocol.processInput(inputLine);
                System.out.println("Server: " + portNumber + " " + outputLine);
                if (!serverSecureProtocol.encryptionDone) {
                    out.println(outputLine);
                    if (outputLine.equals("Bye."))
                        break;

                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


}

