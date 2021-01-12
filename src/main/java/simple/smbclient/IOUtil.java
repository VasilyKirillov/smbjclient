package simple.smbclient;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class IOUtil {

    private static final int EOF = -1;
    private static final int DEFAULT_BUFFER_SIZE = 4096;

    static int copy(final InputStream is, final OutputStream os) throws IOException {
        final long count = copyLarge(is, os, new byte[DEFAULT_BUFFER_SIZE]);
        if (count > Integer.MAX_VALUE) {
            return -1;
        }
        return (int) count;
    }

    private static long copyLarge(InputStream input, OutputStream output, byte[] buffer) throws IOException {
        long count = 0;
        int n;
        while (EOF != (n = input.read(buffer))) {
            output.write(buffer, 0, n);
            count += n;
        }
        return count;
    }
}
