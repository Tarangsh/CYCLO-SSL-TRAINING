package prj.cyclo.NewSSLModule;

import prj.cyclo.SSLTransport;

import java.io.IOException;
import java.net.Socket;

public interface ISSLModule
{
    public void initiateSSLConnection(Socket socket, SSLTransport<Socket> sslTransport, IHandShakeCompletedListenerWithTimeOut handShakeCompletedListenerWithTimeOut);

    public void closeSSLConnection();

    public void decryptData(byte[] data);

    public void send(byte[] data) throws IOException;
}
