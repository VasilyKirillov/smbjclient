package simple.smbclient;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.utils.SmbFiles;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.EnumSet;

public class SimpleSmbClient {
    private static final int REQUIRED_PARAMS_NUMBER = 11;
    private static final String CREDENTIAL_SEPARATOR = "%";

    public static void main(String[] args) {
        SMBJParams params = getArgsMap(args);
        if (params.isEmpty()) {
            printUsage();
            return;
        }
        SMBClient client = new SMBClient();

        try (Connection connection = client.connect(params.host)) {
            String[] userAndPass = params.user.split(CREDENTIAL_SEPARATOR);
            AuthenticationContext ac = new AuthenticationContext(userAndPass[0], userAndPass[1].toCharArray(), null);
            Session session = connection.authenticate(ac);

            try (DiskShare share = (DiskShare) session.connectShare(params.share)) {
                if ("get".equals(params.operation))
                    readFileFromSharedFolder(params, share);
                if ("put".equals(params.operation))
                    writeFileToShare(params, share);
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void readFileFromSharedFolder(SMBJParams params, DiskShare share) throws IOException {
        com.hierynomus.smbj.share.File inputFile = share.openFile(
                params.path,
                EnumSet.of(AccessMask.GENERIC_READ),
                EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ),
                SMB2CreateDisposition.FILE_OPEN,
                EnumSet.noneOf(SMB2CreateOptions.class)
        );
        try (final InputStream is = inputFile.getInputStream();
             final OutputStream os = new FileOutputStream(params.file)) {
            IOUtil.copy(is, os);
        }
    }

    private static void printUsage() {
        System.out.println("smbclient [OPERATION] [OPTIONS]\n\n" +
                "OPERATION:\n\tget\tretrieve file from shared folder\n\tput\tsend file to shared folder\n" +
                "OPTIONS:\n\t--user,-u\tusername%password" +
                "\n\t--host,-h\thost, servername or ip address" +
                "\n\t--share,-s\tname of shared folder" +
                "\n\t--path,-p\tdestination path + filename in shared folder" +
                "\n\t--file,-f\tsource path to local file");
    }

    private static SMBJParams getArgsMap(String[] args) {
        SMBJParams params = new SMBJParams();
        if (args.length < REQUIRED_PARAMS_NUMBER) return params;
        params.operation = args[0];
        for (int i = 1;i < args.length;i++) {
            String arg = args[i];
            if ("--user".equals(arg) || "-u".equals(arg))
                params.user = args[++i];
            else if ("--host".equals(arg) || "-h".equals(arg))
                params.host = args[++i];
            else if ("--share".equals(arg) || "-s".equals(arg))
                params.share = args[++i];
            else if ("--path".equals(arg) || "-p".equals(arg))
                params.path = args[++i];
            else if ("--file".equals(arg) || "-f".equals(arg))
                params.file = args[++i];
            else if ("--debug".equals(arg) || "-d".equals(arg))
                System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "DEBUG");
        }
        return params;
    }

    private static void writeFileToShare(SMBJParams params, DiskShare share) throws IOException {
        createPathIfNotExists(share, params.path);
        File source = new File(params.file);
        SmbFiles.copy(source, share, params.path, Boolean.TRUE);
    }

    private static void createPathIfNotExists(DiskShare share, String path) {
        char backslash = '\\';
        char forwardSlash = '/';
        if (path.indexOf(backslash) >= 0) {
            createPathIfNotExists(share, path, backslash);
        } else if (path.indexOf(backslash) >= 0) {
            createPathIfNotExists(share, path, forwardSlash);
        } else {
            createDirIfNotExist(share, path);
        }
    }

    private static void createPathIfNotExists(DiskShare share, String path, char separator) {
        for (int to, from = 0; from < path.lastIndexOf(separator); from = to) {
            if (from > 0) from += 1;
            to = path.indexOf(separator, from);
            createDirIfNotExist(share, path.substring(0, to + 1));
        }
    }

    private static void createDirIfNotExist(DiskShare share, String path) {
        share.openDirectory(path,
                EnumSet.of(AccessMask.MAXIMUM_ALLOWED),
                EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
                SMB2ShareAccess.ALL,
                SMB2CreateDisposition.FILE_OPEN_IF,
                EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE)
        );
    }

    private static class SMBJParams {
        private String operation;
        private String user;
        private String host;
        private String share;
        private String path;
        private String file;

        boolean isEmpty() {
            return operation == null && user == null && host == null
                    && share == null && path == null && file == null;
        }
    }
}
