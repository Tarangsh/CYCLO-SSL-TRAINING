package prj.cyclo.NewSSLModule;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import java.net.Socket;

public abstract class IHandShakeCompletedListenerWithTimeOut implements HandshakeCompletedListener
{
    @Override
    public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
    {

    }

    public void handshakeFailed(Socket socket)
    {

    }
}
