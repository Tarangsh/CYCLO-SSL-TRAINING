package prj.cyclo;

import org.junit.Test;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static junit.framework.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class SSLManagerTest
{
    @Test
    public void testHandshake() throws Exception
    {
        final Integer CLIENT = 9;
        final Integer SERVER = 10;

        final SSLManager<Integer> sslServer = new SSLManager<>(false);
        final SSLManager<Integer> sslClient = new SSLManager<>(true);

        SSLTransport<Integer> serverTransport = new SSLTransport<Integer>()
        {
            @Override
            public void send(Integer key, byte[] data) throws IOException
            {
                ByteBuffer decryptedData = sslServer.allocateByteBuffer(key, SSLManager.Operation.SENDING);
                System.out.println("S > C: " + data.length);


                System.out.println("SSLClient| Received data");
                sslClient.decrypt(SERVER, data, decryptedData);
                if (!sslClient.isHandshakeCompleted(SERVER))
                {
                    sslClient.shakehands(SERVER);
                }

            }
        };
        SSLTransport<Integer> clientTransport = new SSLTransport<Integer>()
        {
            @Override
            public void send(Integer key, byte[] data) throws IOException
            {
                ByteBuffer decryptedData = sslClient.allocateByteBuffer(key, SSLManager.Operation.SENDING);
                System.out.println("C > S: " + data.length);


                System.out.println("SSLServer| Received data");
                sslServer.decrypt(CLIENT, data, decryptedData);
                if (!sslServer.isHandshakeCompleted(CLIENT))
                {
                    sslServer.shakehands(CLIENT);
                }
            }
        };

        sslServer.setTransport(serverTransport);
        sslClient.setTransport(clientTransport);
        sslServer.prepare(CLIENT);
        sslClient.prepare(SERVER);

        System.out.println("SSLServer| handshake begins");
        sslServer.beginSSLHandshake(CLIENT, new HandshakeCompletedListener()
        {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
            {
                System.out.println("Server Done");
                assertTrue(true);
            }
        });

        System.out.println("SSLCLIENT| handshake begins");
        sslClient.beginSSLHandshake(SERVER, new HandshakeCompletedListener()
        {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
            {
                System.out.println("Client Done");
                assertTrue(true);
            }
        });
    }

    @Test
    public void testDataSent() throws Exception
    {
        final Integer CLIENT = 9;
        final Integer SERVER = 10;

        final SSLManager<Integer> sslServer = new SSLManager<>(false);
        final SSLManager<Integer> sslClient = new SSLManager<>(true);
        final String sampleString = "Test data datadata data data data data data data data data data data data data data data data data  data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data ";
        final byte[] sampleData = sampleString.getBytes();


        SSLTransport<Integer> serverTransport = new SSLTransport<Integer>()
        {
            @Override
            public void send(Integer key, byte[] data) throws IOException
            {
                ByteBuffer decryptedData = sslServer.allocateByteBuffer(key, SSLManager.Operation.SENDING);
                sslClient.decrypt(SERVER, data, decryptedData);
                if (!sslClient.isHandshakeCompleted(SERVER))
                {
                    sslClient.shakehands(SERVER);
                }
            }
        };
        SSLTransport<Integer> clientTransport = new SSLTransport<Integer>()
        {
            @Override
            public void send(Integer key, byte[] data) throws IOException
            {
                ByteBuffer decryptedData = sslClient.allocateByteBuffer(key, SSLManager.Operation.SENDING);
                sslServer.decrypt(CLIENT, data, decryptedData);
                if (sslClient.isHandshakeCompleted(SERVER))
                {
                    byte[] decryptedBytes = Arrays.copyOfRange(decryptedData.array(), 0, decryptedData.position());
                    String decryptedString = new String(decryptedBytes);
                    assertEquals(sampleString.length(), decryptedString.length());
                    assertTrue(sampleString.equals(decryptedString));
                    return;
                }
                if (!sslServer.isHandshakeCompleted(CLIENT))
                {
                    sslServer.shakehands(CLIENT);
                    return;
                }
            }
        };

        sslServer.setTransport(serverTransport);
        sslClient.setTransport(clientTransport);
        sslServer.prepare(CLIENT);
        sslClient.prepare(SERVER);

        sslServer.beginSSLHandshake(CLIENT, new HandshakeCompletedListener()
        {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
            {
                assertTrue(true);
            }
        });

        sslClient.beginSSLHandshake(SERVER, new HandshakeCompletedListener()
        {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
            {
                try
                {
                    ByteBuffer encryptedData = sslClient.allocateByteBuffer(SERVER, SSLManager.Operation.SENDING);
                    sslClient.send(SERVER, sampleData);
                }
                catch (IOException e)
                {
                    fail(e.toString());
                }
            }
        });
    }
}
