package prj.cyclo;

import org.junit.Test;
import prj.cyclo.NewSSLModule.IHandShakeCompletedListenerWithTimeOut;
import prj.cyclo.NewSSLModule.SSLModule;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;

import static org.junit.Assert.assertTrue;

public class SSLModuleTests
{
    @Test
    public void testHandshake() throws Exception
    {
        final Socket clientSocket = new Socket();
        final Socket serverSocket = new Socket();

        final SSLModule sslServer = new SSLModule(false);
        final SSLModule sslClient = new SSLModule(true);



        SSLTransport<Socket> serverTransport = new SSLTransport<Socket>()
        {
            @Override
            public void send(Socket socket, byte[] data) throws IOException
            {
                ByteBuffer decryptedData = sslServer.allocateByteBuffer(SSLModule.Operation.SENDING);
                System.out.println("S > C: " + data.length);


                System.out.println("SSLClient| Received data");
                sslClient.decrypt(data, decryptedData);
                if (!sslClient.isHandshakeComplete())
                {
                    sslClient.shakeHands();
                }

            }
        };
        SSLTransport<Socket> clientTransport = new SSLTransport<Socket>()
        {
            @Override
            public void send(Socket socket, byte[] data) throws IOException
            {
                ByteBuffer decryptedData = sslClient.allocateByteBuffer(SSLModule.Operation.SENDING);
                System.out.println("C > S: " + data.length);


                System.out.println("SSLServer| Received data");
                sslServer.decrypt(data, decryptedData);
                if (!sslServer.isHandshakeComplete())
                {
                    sslServer.shakeHands();
                }
            }
        };

        sslServer.initiateSSLConnection(clientSocket, serverTransport, new IHandShakeCompletedListenerWithTimeOut() {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
            {
                System.out.println("Server Done....");
                assertTrue(true);
            }

            @Override
            public void handshakeFailed(Socket socket) {
                super.handshakeFailed(socket);    //To change body of overridden methods use File | Settings | File Templates.
            }
        });

        sslClient.initiateSSLConnection(serverSocket, clientTransport, new IHandShakeCompletedListenerWithTimeOut() {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
            {
                System.out.println("Client Done....");
                assertTrue(true);
            }

            @Override
            public void handshakeFailed(Socket socket) {
                super.handshakeFailed(socket);    //To change body of overridden methods use File | Settings | File Templates.
            }
        });
    }

}
