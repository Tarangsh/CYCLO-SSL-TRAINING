package prj.cyclo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.channels.SelectionKey;
import java.nio.charset.Charset;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

public abstract class Agent
{
    protected final TCPReactor _reactor;
    protected final ScheduledExecutorService _agency;
    protected SelectionKey _selectionKey;
    Logger _logger = LoggerFactory.getLogger(Agent.class.getSimpleName());

    protected Agent(TCPReactor reactor, ScheduledExecutorService threadPool)
    {
        _reactor = reactor;
        _agency = threadPool;
    }

    public Agent(TCPReactor reactor)
    {
        _agency = Executors.newSingleThreadScheduledExecutor();
        _reactor = reactor;
    }

    public abstract void connectionMade(Socket socket);

    public abstract boolean isServer();

    public abstract InetSocketAddress getSocketAddress() throws UnknownHostException;
    /* Returns the address to bind a server to or the address to connect a client */

    public abstract void receive(Socket socket, byte[] incomingData);

    public void send(Socket socket, byte[] outgoingData) throws IOException
    {
        _reactor.send(this, socket, outgoingData);
    }

    public void send(Socket socket, String outgoingData) throws IOException
    {
        send(socket, outgoingData.getBytes("UTF-8"));
    }

    public void cancelRegistration()
    {
        _selectionKey.cancel();
    }

    public void close(Socket socket)
    {
        _reactor.close(socket);
    }

    public void submit(final Runnable r)
    {
        Runnable runnable = new Runnable()
        {
            @Override
            public void run()
            {
                try
                {
                    r.run();
                }
                catch (Exception e)
                {
                    _logger.error("exception in task submitted to Agency", e);
                    _agency.shutdown();
                }
            }
        };
        _agency.submit(runnable);
    }

    public void setSelectionKey(SelectionKey k)
    {
        _selectionKey = k;
    }

    public abstract void registrationFailed(IOException e);

    public void onClose(Socket socket)
    {

    }

    public abstract void onShutdown();
}
