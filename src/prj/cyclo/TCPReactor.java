package prj.cyclo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.*;

public class TCPReactor //Singleton
{
    private static volatile TCPReactor _reactor;
    private Selector _selector;
    private boolean _doShutdown;
    private ByteBuffer _buffer;
    private final Map<Socket, ByteArrayOutputStream> _pendingData;
    private final List<Socket> _closePendingSockets;
    private final List<Agent> _pendingRegistrations;
    private final Logger _logger = LoggerFactory.getLogger(this.getClass().getSimpleName());

    private TCPReactor() throws IOException
    {
        _closePendingSockets = new ArrayList<>();
        _selector = Selector.open();
        _buffer = ByteBuffer.allocate(1024 * 64);
        _pendingData = Collections.synchronizedMap(new HashMap<Socket, ByteArrayOutputStream>());
        _pendingRegistrations = Collections.synchronizedList(new ArrayList<Agent>());
    }

    public static TCPReactor initiate() throws IOException
    {
        if (_reactor == null)
        {
            _reactor = new TCPReactor();
        }
        return _reactor;
    }

    public void register(Agent agent)
    {
        _pendingRegistrations.add(agent);
        _selector.wakeup();
    }

    public void shutdown()
    {
        _doShutdown = true;
        try
        {
            for (SelectionKey k : _selector.keys())
            {
                Agent agent = (Agent) k.attachment();
                if (k.channel() instanceof SocketChannel)
                {
                    SocketChannel c = (SocketChannel) k.channel();
                    c.socket().close();
                    notifyAgentSocketChannelClosed(c.socket(), agent);
                }
                else if (k.channel() instanceof ServerSocketChannel)
                {
                    ServerSocketChannel c = (ServerSocketChannel) k.channel();
                    c.socket().close();
                    notifyAgentServerSocketChannelClosed(agent);
                }
            }
        }
        catch (IOException ignored)
        {
            _logger.debug("Exception while closing socket while shutting down, ignoring");
        }

        try
        {
            _selector.close();
        }
        catch (IOException ignored)
        {
            _logger.debug("Ignoring IOException in shutdown", ignored);
        }
    }

    public void fire() throws IOException
    {
        while (true)
        {
            if (_doShutdown)
            {
                closeSelector();
                break;
            }
            _selector.select();
            processPendingRegistrations();
            processSelectedKeys();
            processSocketsPendingForClosure();
        }

    }

    private void processSelectedKeys() throws IOException
    {
        Set<SelectionKey> selectedKeys = _selector.selectedKeys();
        Iterator<SelectionKey> iter = selectedKeys.iterator();
        while (iter.hasNext())
        {
            final SelectionKey key = iter.next();
            if (key.isValid())
            {
                try
                {
                    if (key.isAcceptable())
                    {
                        handleAccept(key);
                    }

                    if (key.isConnectable())
                    {
                        handleConnect(key);
                    }

                    if (key.isReadable())
                    {
                        read(key);
                    }

                    if (key.isWritable())
                    {
                        write(key);
                    }
                }
                catch (CancelledKeyException | IOException e)
                {
                    Agent agent = (Agent) key.attachment();
                    if (key.channel() instanceof SocketChannel)
                    {
                        final SocketChannel channel = (SocketChannel) key.channel();
                        closeNow(channel.socket());
                        key.cancel(); //idempotent
                        notifyAgentSocketChannelClosed(channel.socket(), agent);
                    }
                    else if (key.channel() instanceof ServerSocketChannel)
                    {
                        _logger.error("exception in server socket channel", e);
                        ServerSocketChannel serverSocketChannel = (ServerSocketChannel) key.channel();
                        serverSocketChannel.socket().close();
                        notifyAgentServerSocketChannelClosed(agent);
                    }
                }
            }
            iter.remove();
        }
    }

    private void handleConnect(SelectionKey key) throws IOException
    {
        final SocketChannel socketChannel = (SocketChannel) key.channel();

        final Agent agent = (Agent) key.attachment();
        boolean finishedConnection = false;

        try
        {
            finishedConnection = socketChannel.finishConnect();
        }
        catch (IOException e)
        {
            socketChannel.close();
        }

        if (finishedConnection)
        {
            registerOp(SelectionKey.OP_READ, socketChannel, agent);
            informAgentOfConnection(socketChannel, agent);
        }
    }

    private void handleAccept(SelectionKey key) throws IOException
    {
        ServerSocketChannel serverChannel = (ServerSocketChannel) key.channel();
        final SocketChannel socketChannel = serverChannel.accept();
        if (socketChannel != null)
        {
            handleAcceptedSocket(key, socketChannel);
        }
        else
        {
            _logger.error("accepted socket channel is null");
        }
    }

    private void handleAcceptedSocket(SelectionKey key, SocketChannel socketChannel)
    {
        Socket acceptedSocket = socketChannel.socket();
        if (acceptedSocket == null)
        {
            _logger.error("accepted socket is null");
        }
        else
        {
            try
            {
                acceptedSocket.setKeepAlive(true);
                socketChannel.configureBlocking(false);
                final Agent agent = (Agent) key.attachment();
                registerOp(SelectionKey.OP_READ, socketChannel, agent);
                informAgentOfConnection(socketChannel, agent);
            }
            catch (IOException e)
            {
                _logger.error("error in accepted socket handling", e);
            }
        }
    }

    private static void informAgentOfConnection(final SocketChannel socketChannel, final Agent agent)
    {
        Runnable r = new Runnable()
        {
            public void run()
            {
                agent.connectionMade(socketChannel.socket());
            }
        };
        agent.submit(r);
    }

    private void registerAgent(Agent agent) throws IOException
    {
        if (agent.isServer())
        {
            ServerSocketChannel serverChannel = ServerSocketChannel.open();
            serverChannel.configureBlocking(false);
            InetSocketAddress bindAddress = agent.getSocketAddress();
            ServerSocket serverSocket = serverChannel.socket();
            serverSocket.bind(bindAddress);
            SelectionKey k = serverChannel.register(_selector, SelectionKey.OP_ACCEPT, agent);
            agent.setSelectionKey(k);
        }
        else
        {
            SocketChannel socketChannel = SocketChannel.open();
            socketChannel.configureBlocking(false);
            socketChannel.connect(agent.getSocketAddress());
            SelectionKey k = socketChannel.register(_selector, SelectionKey.OP_CONNECT, agent);
            agent.setSelectionKey(k);
        }
    }


    private void processPendingRegistrations()
    {
        synchronized (_pendingRegistrations)
        {
            Iterator<Agent> iterator = _pendingRegistrations.iterator();
            while (iterator.hasNext())
            {
                Agent n = iterator.next();
                try
                {
                    registerAgent(n);
                }
                catch (IOException e)
                {
                    n.registrationFailed(e);
                }
                iterator.remove();
            }
        }
    }

    private void write(SelectionKey key) throws IOException
    {
        SocketChannel socketChannel = (SocketChannel) key.channel();
        Socket socket = socketChannel.socket();
        Agent agent = (Agent) key.attachment();
        synchronized (_pendingData)
        {
            ByteArrayOutputStream data = _pendingData.get(socket);
            if (data != null)
            {
                if (data.size() > 0)
                {
                    ByteBuffer buffer = ByteBuffer.wrap(data.toByteArray());
                    int written = socketChannel.write(buffer);
                    if (written < data.size())
                    {
                        byte[] remainingDataArray = Arrays.copyOfRange(data.toByteArray(), written, data.size());
                        ByteArrayOutputStream remainingData = new ByteArrayOutputStream();
                        remainingData.write(remainingDataArray);
                        _pendingData.put(socket, remainingData);
                        registerOp(SelectionKey.OP_WRITE | SelectionKey.OP_READ, socketChannel, agent);
                    }
                    else
                    {
                        _pendingData.remove(socket);
                        //Only register for read as we don't want to be informed for a writable ops
                        //unless we have pending data to send, this is because writable will be true almost
                        //all the time.
                        registerOp(SelectionKey.OP_READ, socketChannel, agent);
                    }
                }
            }
        }
    }

    private void read(SelectionKey key) throws IOException
    {
        SocketChannel socketChannel = (SocketChannel) key.channel();
        final Socket socket = socketChannel.socket();
        if (isMarkedForClosing(socket))
        {
            return;
        }
        final Agent agent = (Agent) key.attachment();

        _buffer.clear();
        int count;
        while ((count = socketChannel.read(_buffer)) > 0)
        {
            _buffer.flip();
            final byte[] incomingData = copyBytes(_buffer);
            Runnable r = new Runnable()
            {
                public void run()
                {
                    agent.receive(socket, incomingData);
                }
            };
            agent.submit(r);
            _buffer.clear();
        }

        if (count < 0)
        { //Client has disconnected
            notifyAgentSocketChannelClosed(socket, agent);
            closeNow(socket);
        }
    }


    private boolean isMarkedForClosing(Socket socket)
    {
        return _closePendingSockets.contains(socket);
    }

    private static byte[] copyBytes(ByteBuffer buffer)
    {
        final byte[] incomingData = new byte[buffer.remaining()];
        buffer.get(incomingData);
        return incomingData;
    }

    public void send(Agent agent, Socket socket, byte[] data) throws IOException
    {
        synchronized (_pendingData)
        {
            ByteArrayOutputStream existingData = _pendingData.get(socket);
            if (existingData == null)
            {
                existingData = new ByteArrayOutputStream();
            }
            existingData.write(data);
            _pendingData.put(socket, existingData);
        }
        SocketChannel channel = socket.getChannel();
        try
        {
            registerOp(SelectionKey.OP_WRITE | SelectionKey.OP_READ, channel, agent);
            _selector.wakeup();
        }
        catch (ClosedChannelException | CancelledKeyException e)
        {
            _pendingData.remove(socket);//Forces the following close() call to close immediately
            close(socket);
            throw new IOException(e);
        }
    }

    private void registerOp(int op, SocketChannel channel, Agent agent) throws ClosedChannelException
    {
        channel.register(_selector, op, agent);
    }

    private void closeSelector()
    {
        try
        {
            _selector.close();
        }
        catch (IOException exception)
        {
            _logger.debug("Ignoring IOException in closeSelector", exception);
        }
    }


    public void close(Socket socket)
    {
        if (hasPendingData(socket))
        {
            markForClosure(socket);
        }
        else
        {
            closeNow(socket);
        }
    }

    private boolean hasPendingData(Socket socket)
    {
        synchronized (_pendingData)
        {
            ByteArrayOutputStream pending = _pendingData.get(socket);
            return (pending != null) && (pending.size() > 0);
        }
    }

    private void markForClosure(Socket socket)
    {
        synchronized (_closePendingSockets)
        {
            _closePendingSockets.add(socket);
        }
    }

    private void closeNow(Socket socket)
    {
        synchronized (_pendingData)
        {
            _pendingData.remove(socket);
            try
            {
                final SocketChannel channel = socket.getChannel();
                channel.close();
                socket.close();
            }
            catch (IOException e)
            {
                _logger.debug("Ignoring IOException in closeNow ", e);
            }
            catch (NullPointerException e)
            {
                _logger.error("Ignoring null pointer exception in closeNow", e);
            }
        }
    }

    private void processSocketsPendingForClosure()
    {
        if (_closePendingSockets.size() > 0)
        {
            synchronized (_closePendingSockets)
            {
                Iterator<Socket> iter = _closePendingSockets.iterator();
                while (iter.hasNext())
                {
                    Socket s = iter.next();
                    if (!hasPendingData(s))
                    {
                        iter.remove();
                        closeNow(s);
                    }
                }
            }
        }
    }

    private void notifyAgentServerSocketChannelClosed(final Agent agent)
    {
        Runnable runnable = new Runnable()
        {
            @Override
            public void run()
            {
                agent.onShutdown();
            }
        };
        agent.submit(runnable);
    }

    private void notifyAgentSocketChannelClosed(final Socket socket, final Agent agent)
    {
        Runnable r = new Runnable()
        {
            public void run()
            {
                agent.onClose(socket);
            }
        };
        agent.submit(r);
    }

}
