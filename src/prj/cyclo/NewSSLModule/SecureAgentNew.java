package prj.cyclo.NewSSLModule;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import prj.cyclo.Agent;
import prj.cyclo.SSLManager;
import prj.cyclo.SSLTransport;
import prj.cyclo.TCPReactor;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public abstract class SecureAgentNew extends Agent
{
    private static final long HANDSHAKE_TIMEOUT_IN_SECONDS = 60;
    private SSLModule _sslModule;
    private SSLTransport<Socket> _sslTransport;
    private final Logger _logger = LoggerFactory.getLogger(this.getClass().getSimpleName());
    private final Map<Socket, ScheduledFuture> _handshakeTimeoutTasks = new HashMap<>();

    protected SecureAgentNew(TCPReactor reactor, ScheduledExecutorService threadPool, SSLModule ssl_module)
    {
        super(reactor, threadPool);
        setupSSL(ssl_module);
    }


    public SecureAgentNew(TCPReactor reactor, SSLModule ssl_module)
    {
        super(reactor);
        setupSSL(ssl_module);
    }

    private void setupSSL(SSLModule ssl_module)
    {
        _sslModule = ssl_module;

        _sslTransport = new SSLTransport<Socket>()
        {
            public void send(Socket socket, byte[] data) throws IOException
            {
                SecureAgentNew.super.send(socket, data);
            }
        };
    }

    public abstract void secureConnectionMade(Socket socket);

    public abstract void secureReceive(Socket socket, byte[] incomingData);

    @Override
    public final void connectionMade(final Socket socket)
    {
        _sslModule.initiateSSLConnection(socket,_sslTransport, new IHandShakeCompletedListenerWithTimeOut()
        {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
            {
                secureConnectionMade(socket);
            }

            @Override
            public void handshakeFailed(Socket socket)
            {
                close(socket);
            }
        });
    }

    public final void receive(Socket socket, byte[] incomingData)
    {
        try
        {
            ByteBuffer decryptedData = _sslModule.allocateByteBuffer(SSLModule.Operation.RECEIVING);
            if (decryptedData != null)
            {
                _sslModule.decrypt(incomingData, decryptedData);
                byte[] decryptedBytes = Arrays.copyOfRange(decryptedData.array(), 0, decryptedData.position());
             /*   if (_sslModule.isHandshakeCompleted(socket))
                {
                    secureReceive(socket, decryptedBytes);
                }
                else
                {
                    _sslManager.shakehands(socket);
                }*/
            }
            else
            {
                close(socket);
            }
        }
        catch (Exception e)
        {
            if (e instanceof IOException)
            {
                _logger.debug("IOException in SecureAgent.receive, closing socket: {}", socket);
            }
            else
            {
                _logger.error("Exception in SecureAgent.receive, closing socket: ", e);
            }
            close(socket);
        }

    }

    public final void secureSend(Socket socket, byte[] plainData) throws IOException
    {
        try
        {
            _sslModule.send(plainData);
        }
        catch (Exception e)
        {
            if (e instanceof IOException)
            {
                _logger.info("IOException in secure send: {}", socket);
            }
            else
            {
                _logger.error("exception in secure send: ", e);
            }
            throw new IOException(e);
        }
    }

    @Override
    public final void close(Socket socket)
    {
        cancelHandshakeTimeoutTask(socket);
        _sslModule.closeSSLConnection();
        super.close(socket);
        secureClose(socket);
    }

    @Override
    public void onClose(Socket socket)
    {
        close(socket);
    }

    public void secureClose(Socket socket)
    {
        //Extending class should override this
    }

    @Override
    public final void send(Socket socket, byte[] data) throws IOException
    {
        secureSend(socket, data);
    }

    private void cancelHandshakeTimeoutTask(Socket socket)
    {
        ScheduledFuture handshakeTimeoutTask = _handshakeTimeoutTasks.remove(socket);
        if (handshakeTimeoutTask != null)
        {
            handshakeTimeoutTask.cancel(false);
        }
    }

}

