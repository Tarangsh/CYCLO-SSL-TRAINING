package prj.cyclo.NewSSLModule;

import prj.cyclo.SSLTransport;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SSLModule implements ISSLModule
{
    private SSLContext mSSLContext;
    private boolean mClientMode;
    private boolean mIsHandShakeComplete;
    private java.net.Socket mSocket;
    private SSLEngine mSSLEngine;
    private SSLTransport<Socket> mSSLTransPort;
    private List<IHandShakeCompletedListenerWithTimeOut> mHandshakeCompletedListeners = new ArrayList<IHandShakeCompletedListenerWithTimeOut>();
    private byte[] mRemainingData = new byte[2000];
    private static final long HANDSHAKE_TIME_OUT_IN_SECONDS = 60;

    public SSLModule(boolean clientMode) throws IOException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, UnrecoverableKeyException
    {

        mClientMode = clientMode;
        mSSLContext = getSSLContext();
        mIsHandShakeComplete = false;
        initializeSSLEngine();
    }

    @Override
    public void initiateSSLConnection(Socket socket, SSLTransport<Socket> sslTransport, IHandShakeCompletedListenerWithTimeOut handShakeCompletedListenerWithTimeOut)
    {
        mSocket = socket;
        mSSLTransPort = sslTransport;
        mHandshakeCompletedListeners.add(handShakeCompletedListenerWithTimeOut);

        try
        {
            mSSLEngine.beginHandshake();
            shakeHands();
        }
        catch (Exception e)
        {
            fireHandshakeFailure();
        }
    }

    @Override
    public void closeSSLConnection()
    {
        try
        {
            if (mSSLEngine != null)
            {
                mSSLEngine.closeOutbound();
                mSSLEngine.closeInbound();
            }
        }
        catch (IOException ignored)
        {

        }
        cleanState();
    }

    @Override
    public void decryptData(byte[] data)
    {

    }

    @Override
    public void send(byte[] plainBytes) throws IOException
    {
        ByteBuffer encryptedData = allocateByteBuffer(Operation.SENDING);
        SSLEngineResult result;
        int totalBytesConsumed = 0;
        do
        {
            result = encrypt(Arrays.copyOfRange(plainBytes, totalBytesConsumed, plainBytes.length), encryptedData);
            byte[] sendableData = copyToByteArray(encryptedData, result.bytesProduced());
            mSSLTransPort.send(mSocket, sendableData);
            encryptedData.clear();
            totalBytesConsumed += result.bytesConsumed();
        }
        while (result.getStatus().equals(SSLEngineResult.Status.OK) && totalBytesConsumed < plainBytes.length && result.bytesProduced() > 0);
    }

    public boolean isHandshakeComplete()
    {
        return mIsHandShakeComplete;
    }

    //PRIVATE METHODS
    private void initializeSSLEngine()
    {
        mSSLEngine = mSSLContext.createSSLEngine();
        mSSLEngine.setUseClientMode(mClientMode);
        mSSLEngine.setNeedClientAuth(false);
    }

    public void shakeHands() throws IOException
    {
        while (true)
        {
            SSLEngineResult.HandshakeStatus handshakeStatus = mSSLEngine.getHandshakeStatus();
            System.out.println("HANDSHAKE STATUS: " + handshakeStatus);
            switch (handshakeStatus)
            {
                case FINISHED:
                    finishHandshake();
                    mIsHandShakeComplete = true;
                    return;
                case NOT_HANDSHAKING:
                    return;
                case NEED_TASK:
                    processLongRunningTask();
                    break;
                case NEED_WRAP:
                    SSLEngineResult result = wrapAndSend();
                    if (isHandshakeStatusFinished(result))
                    {
                        System.out.println("QQQQ HANDSHAKE FINISHED");
                        finishHandshake();
                        return;
                    }
                    break;
                case NEED_UNWRAP:
                    if (mRemainingData.length > 0)
                    {
                        ByteBuffer decryptedData = allocateByteBuffer(Operation.RECEIVING);
                        SSLEngineResult unwrapResult = decrypt(new byte[0], decryptedData);
                        if (unwrapResult.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP))
                        {
                            return;
                        }
                        else if (isHandshakeStatusFinished(unwrapResult))
                        {
                            finishHandshake();
                            return;
                        }
                        else
                        {
                            break;
                        }
                    }
                    return;
            }
        }
    }

    private static SSLContext getSSLContext() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, KeyManagementException, UnrecoverableKeyException
    {
        String password = "android@39";
        char[] passphrase = password.toCharArray();
        // First initialize the key and trust material.
        String keystore = "/home/tarang/CodeBase/ssc-android/android-ssc.jks";
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream stream = new FileInputStream(keystore);
        ks.load(stream, passphrase);
        stream.close();
        SSLContext sslContext = SSLContext.getInstance("TLS");

        // TrustManager's decide whether to allow connections.
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        // KeyManager's decide which key material to use.
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, passphrase);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return sslContext;
    }

    private void finishHandshake()
    {
        System.out.println("QQQQ HANDSHAKE FINISHED");
        for(IHandShakeCompletedListenerWithTimeOut handShakeCompletedListenerWithTimeOut : mHandshakeCompletedListeners)
        {
            handShakeCompletedListenerWithTimeOut.handshakeCompleted(null);
        }
        mHandshakeCompletedListeners = new ArrayList<>();
    }

    private void processLongRunningTask()
    {
        Runnable task;
        while ((task = mSSLEngine.getDelegatedTask()) != null)
        {
            task.run();
        }
    }

    private SSLEngineResult wrapAndSend() throws IOException
    {
        ByteBuffer encryptedData = allocateByteBuffer(Operation.SENDING);
        SSLEngineResult result = encrypt(new byte[0], encryptedData);
        encryptedData.flip();

        byte[] sslMessage = getSSLMessageBytesFromBuffer(encryptedData, result);
        mSSLTransPort.send(mSocket, sslMessage);
        return result;
    }

    public ByteBuffer allocateByteBuffer(Operation operation) throws IOException
    {
        SSLSession session = mSSLEngine.getSession();
        int bufferSize;
        if (operation == Operation.SENDING)
        {
            bufferSize = session.getPacketBufferSize();
        }
        else
        {
            bufferSize = session.getApplicationBufferSize();
        }
        return ByteBuffer.allocate(bufferSize);
    }

    private static byte[] getSSLMessageBytesFromBuffer(ByteBuffer encryptedData, SSLEngineResult result)
    {
        byte[] sslMessage = new byte[result.bytesProduced()];
        encryptedData.get(sslMessage, 0, result.bytesProduced());
        return sslMessage;
    }

    private SSLEngineResult encrypt(byte[] data, ByteBuffer outgoingData) throws IOException
    {
        ByteBuffer applicationData = ByteBuffer.wrap(data);
        return mSSLEngine.wrap(applicationData, outgoingData);
    }

    public SSLEngineResult decrypt(byte[] incomingBytes, ByteBuffer decryptedData) throws IOException
    {
        ByteBuffer encryptedData = getDataForDecryption(incomingBytes);
        try
        {
            SSLEngineResult result = unwrap(decryptedData, encryptedData);
            storeUnprocessedData(encryptedData);
            if (isHandshakeStatusFinished(result))
            {
                finishHandshake();
            }
            return result;
        }
        catch (IOException exception)
        {
            //_logger.info("sslexception while decrypting data: {} {}", new String(incomingBytes), exception);
            throw exception;
        }
    }

    private ByteBuffer getDataForDecryption(byte[] encryptedData)
    {
        int length_remainingData = mRemainingData.length;
        int length_encryptedData = encryptedData.length;
        ByteBuffer totalIncomingData = ByteBuffer.allocate(length_remainingData + length_encryptedData);

        addPendingData(mRemainingData, totalIncomingData);
        addLatestData(encryptedData, totalIncomingData);

        totalIncomingData.flip();
        return totalIncomingData;
    }

    private SSLEngineResult unwrap(ByteBuffer unwrappedData, ByteBuffer totalIncomingData) throws IOException
    {
        SSLEngineResult result;
        int totalBytesConsumed = 0;
        int totalBytesToBeConsumed = totalIncomingData.array().length;
        do
        {
            result = mSSLEngine.unwrap(totalIncomingData, unwrappedData);
            totalBytesConsumed = totalBytesConsumed + result.bytesConsumed();
        }
        while (needsUnwrap(result, totalBytesConsumed, totalBytesToBeConsumed));
        return result;
    }

    private boolean needsUnwrap(SSLEngineResult result, int totalBytesConsumed, int totalBytesToBeConsumed)
    {
        if (!mIsHandShakeComplete)
        {
            return result.getStatus() == SSLEngineResult.Status.OK && result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP) && result.bytesProduced() == 0;
        }
        else
        {
            return result.getStatus() == SSLEngineResult.Status.OK && (result.bytesProduced() != 0 || totalBytesConsumed < totalBytesToBeConsumed);
        }
    }

    private static boolean isHandshakeStatusFinished(SSLEngineResult result)
    {
        return result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.FINISHED);
    }

    private void storeUnprocessedData(ByteBuffer totalIncomingData)
    {
        mRemainingData = Arrays.copyOfRange(totalIncomingData.array(), totalIncomingData.position(), totalIncomingData.limit());
    }

    private static void addLatestData(byte[] encryptedData, ByteBuffer totalIncomingData)
    {
        if (encryptedData.length > 0)
        {
            totalIncomingData.put(encryptedData);
        }
    }

    private void addPendingData(byte[] remainingData, ByteBuffer totalIncomingData)
    {
        if (remainingData.length > 0)
        {
            totalIncomingData.put(remainingData);
            mRemainingData = new byte[0];
        }
    }

    private static byte[] copyToByteArray(ByteBuffer outgoingData, int size)
    {
        outgoingData.flip();
        byte[] bytes = new byte[size];
        outgoingData.get(bytes, 0, size);
        return bytes;
    }

    private void fireHandshakeFailure()
    {
        for (IHandShakeCompletedListenerWithTimeOut handShakeCompletedListenerWithTimeOut : mHandshakeCompletedListeners)
        {
            handShakeCompletedListenerWithTimeOut.handshakeFailed(mSocket);
        }
    }

    private void cleanState()
    {
        mSSLEngine = null;
        mHandshakeCompletedListeners = new ArrayList<>();
        mRemainingData = new byte[2000];
        mIsHandShakeComplete = false;
    }

    public enum Operation
    {
        SENDING, RECEIVING
    }
}
