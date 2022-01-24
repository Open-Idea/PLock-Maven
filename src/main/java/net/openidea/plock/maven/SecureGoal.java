package net.openidea.plock.maven;

import net.openidea.plock.EncryptData;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.apache.maven.shared.model.fileset.FileSet;
import org.apache.maven.shared.model.fileset.util.FileSetManager;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

@Mojo(name = "secure", threadSafe = true, requiresProject = true, requiresDependencyResolution = ResolutionScope.RUNTIME, defaultPhase = LifecyclePhase.PACKAGE)
public class SecureGoal extends AbstractMojo {

    private static final byte[] MAGIC_NUMBER = new byte[] {'P', 'L', 'O', 'K'};
    private static final String[] DEFAULT_INCLUDES = new String[] { "**/**.class" };
    private static final String[] DEFAULT_EXCLUDES = new String[0];

    @Parameter(property = "project", readonly = true)
    private MavenProject project;

    @Parameter(property = "plock.private_key")
    private String privateKey;

    @Parameter(property = "plock.generate_key", defaultValue = "false")
    private boolean generateKey;

    @Parameter(defaultValue = "${project.build.outputDirectory}", required = true)
    private File classesDirectory;

    @Parameter
    private String[] includes;

    @Parameter
    private String[] excludes;

    private RSAPrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        final byte[] decodedKey;
        final KeyFactory keyFactory;

        if (this.privateKey == null || this.privateKey.isEmpty())
            return null;
        decodedKey = Base64.getDecoder().decode(this.privateKey);
        keyFactory = KeyFactory.getInstance("AES");
        return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
    }

    private String encodeKeyToBase64(final Key key) {
        if (key == null)
            return null;
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        keyPairGenerator.initialize(4096);
        return keyPairGenerator.generateKeyPair();
    }

    @Override
    public void execute() {
        final FileSetManager fileSetManager = new FileSetManager();
        final FileSet jarContentFileSet = new FileSet();
        final String[] includedFiles;
        RSAPrivateKey privateKey;
        KeyPair keyPair = null;

        getLog().error("PATH: " + this.classesDirectory.getAbsolutePath());
        jarContentFileSet.setDirectory(this.classesDirectory.getAbsolutePath());
        jarContentFileSet.setIncludes(Arrays.asList((this.includes != null && this.includes.length > 0) ? this.includes : SecureGoal.DEFAULT_INCLUDES));
        jarContentFileSet.setExcludes(Arrays.asList((this.excludes != null && this.excludes.length > 0) ? this.excludes : SecureGoal.DEFAULT_EXCLUDES));
        includedFiles = fileSetManager.getIncludedFiles(jarContentFileSet);
        if (includedFiles.length < 1)
            return;
        try {
            privateKey = getPrivateKey();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return;
        }
        if (privateKey == null) {
            if (!this.generateKey) {
                getLog().warn("No private key set.");
                return;
            }
            try {
                keyPair = generateKeyPair();
            } catch (NoSuchAlgorithmException e) {
                getLog().error("Error to generate RSA key pair: " + e.getMessage());
            }
            if (keyPair == null)
                return;
            privateKey = (RSAPrivateKey) keyPair.getPrivate();
            if (privateKey == null)
                return;
            getLog().info("Private Key: " + encodeKeyToBase64(privateKey));
            getLog().info("Public Key: " + encodeKeyToBase64(keyPair.getPublic()));
        }
        for (String includeFile : includedFiles) {
            getLog().info("Encrypt " + includeFile + " ...");
            try {
                EncryptData.encryptFile(getLog(), Paths.get(this.classesDirectory.getAbsolutePath(), includeFile), privateKey);
            } catch (IOException exception) {
                getLog().error("Error to encrypt " + includeFile + " file.");
                getLog().error(exception);
            }
        }
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
