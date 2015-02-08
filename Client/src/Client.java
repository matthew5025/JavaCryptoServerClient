import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

/**
 * Created by Nathaniel on 20/1/2015.
 */
public class Client {


    public static void main(String[] args) throws Exception {

        String hostName = "localhost";
        int portNumber = 9000;

        try (
                Socket kkSocket = new Socket(hostName, 9000);
                PrintWriter out = new PrintWriter(kkSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(kkSocket.getInputStream()));
        ) {

            String inputLine, outputLine;
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));


            ClientSecureProtocol clientSecureProtocol = new ClientSecureProtocol();

            while (true) {

                if (clientSecureProtocol.isEncrypted) {
                    String messageIn = stdIn.readLine();
                    if (messageIn == null) {
                        break;
                    }
                    outputLine = clientSecureProtocol.processInput(messageIn);
                    out.println(outputLine);
                    System.out.println("OK");
                } else {
                    if ((inputLine = in.readLine()) != null) {
                        outputLine = clientSecureProtocol.processInput(inputLine);
                        out.println(outputLine);
                    }

                }

            }


        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}


