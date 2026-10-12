// Sample Java Applet demonstrating system-level operations and syscall equivalents
import java.applet.Applet;
import java.awt.Graphics;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.Socket;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class SampleApplet extends Applet {

    @Override
    public void init() {
        System.out.println("Initializing Applet...");
        performFileOperations();
        performNetworkOperations();
        executeHostProcess();
    }

    public void performFileOperations() {
        try {
            File targetFile = new File("/tmp/applet_payload.bin");
            FileOutputStream fos = new FileOutputStream(targetFile);
            fos.write(new byte[]{0x41, 0x42, 0x43});
            fos.close();

            FileInputStream fis = new FileInputStream(targetFile);
            fis.read();
            fis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void performNetworkOperations() {
        try {
            Socket sock = new Socket("127.0.0.1", 4444);
            sock.getOutputStream().write("CONNECT".getBytes());
            sock.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void executeHostProcess() {
        // High severity system call invocation from applet
        try {
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                try {
                    Runtime.getRuntime().exec("/bin/sh");
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
                return null;
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void paint(Graphics g) {
        g.drawString("Sample Security Applet", 20, 20);
    }
}
