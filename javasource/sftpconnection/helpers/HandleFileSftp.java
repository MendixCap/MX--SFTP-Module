package sftpconnection.helpers;

import sftpconnection.proxies.AuthenticationType;
import sftpconnection.proxies.KnownHosts;
import sftpconnection.proxies.PassPhraseEntry;
import sftpconnection.proxies.PrivateKey;
import sftpconnection.proxies.PrivateKeyConnection;
import sftpconnection.proxies.PublicKey;
import sftpconnection.proxies.SFTPFileDocument;
import sftpconnection.proxies.SFTPConfiguration;
import system.proxies.FileDocument;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Locale;
import java.util.Vector;

import org.apache.commons.io.IOUtils;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.ChannelSftp.LsEntry;
import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.KeyPair;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpATTRS;
import com.jcraft.jsch.SftpException;
import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.logging.ILogNode;
import com.mendix.systemwideinterfaces.MendixRuntimeException;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;

public class HandleFileSftp {
	
	public static HashMap<String, Session> userSession = new HashMap<String, Session>();

	private static MendixLogger mxLogger;
	static ILogNode logger = Core.getLogger("SFTP module");
	
	static {
		mxLogger = new MendixLogger();
		JSch.setLogger(mxLogger);
	}
	
	
	public static ChannelSftp createSFTPChannel(Session session) throws JSchException {
		if(userSession.containsKey(session.getUserName())){
			session = userSession.get(session.getUserName());
		} else{
			session = ConnectSession(session);
		}
			Channel channel = session.openChannel("sftp");
			channel.connect();
			ChannelSftp sftpChannel = (ChannelSftp) channel;
			return sftpChannel;
		} 
	
	private static Session ConnectSession(Session session) throws JSchException{
		session.connect();
		userSession.put(session.getUserName(), session);

		return session;
	}

	public static byte[] getBytesPrivateKey(SFTPConfiguration sftpConfiguration, IContext context) throws CoreException, IOException {
		AuthenticationType authenticationType = sftpConfiguration.getAuthenticationType();
			if (authenticationType == AuthenticationType.Username_and_connection_specific_private_key) {
				PrivateKeyConnection privateKeyConnection = sftpConfiguration.getSFTPConfiguration_PrivateKey_Connection();
				if (!privateKeyConnection.getHasContents()) {
					return null;
				}
				InputStream streamPrivateKeyConnection = Core.getFileDocumentContent(context, privateKeyConnection.getMendixObject());
				return IOUtils.toByteArray(streamPrivateKeyConnection);
			}
			if (authenticationType == AuthenticationType.Username_and_general_private_key) {
				IMendixObject privateKeyMendix = Core.execute(context, "SFTPConnection.PrivateKey_GetOrCreatePrivateKey");
				PrivateKey privateKey = PrivateKey.initialize(context, privateKeyMendix);
				if (!privateKey.getHasContents()){
					return null;
				}
				InputStream streamPrivateKey = Core.getFileDocumentContent(context, privateKey.getMendixObject());
				return IOUtils.toByteArray(streamPrivateKey);
			}
			return null;
	}

	public static byte[] getBytesPassPhrase(SFTPConfiguration sftpConfiguration, IContext context) throws CoreException, IOException {
		AuthenticationType authenticationType = sftpConfiguration.getAuthenticationType();
			if (authenticationType == AuthenticationType.Username_and_connection_specific_private_key) {
				PrivateKeyConnection privateKeyConnection = sftpConfiguration.getSFTPConfiguration_PrivateKey_Connection(); 	
				String passPhraseConnection = privateKeyConnection.getPassPhrase();
				if (passPhraseConnection == null || passPhraseConnection == "") {
					return null;
				}
				return passPhraseConnection.getBytes();
			}
			if (authenticationType == AuthenticationType.Username_and_general_private_key) {
				IMendixObject privateKeyMendix = Core.execute(context, "SFTPConnection.PrivateKey_GetOrCreatePrivateKey");
				PrivateKey privateKey = PrivateKey.initialize(context, privateKeyMendix);
				String passPhrase = privateKey.getPassPhrase();
				if (passPhrase == null || passPhrase == "") {
					return null;
				}
				return passPhrase.getBytes();
			}
			return null;
	}
	
	public static Session createSession(SFTPConfiguration sftpConfiguration, IContext context) throws JSchException, CoreException, IOException {
		String user = sftpConfiguration.getUsername();
		String host = sftpConfiguration.getHostname();
		String password = sftpConfiguration.getPassword();
		Integer port = sftpConfiguration.getPort();
		AuthenticationType authenticationType = sftpConfiguration.getAuthenticationType();
		
		byte[] privateKey = getBytesPrivateKey(sftpConfiguration, context);
		byte[] passPhrase = getBytesPassPhrase(sftpConfiguration, context); 

		JSch jsch = new JSch();
		java.util.Properties config = new java.util.Properties();
	
		
		
		
		if (!sftpConfiguration.getStrictHostkeyChecking()) {
			config.put("StrictHostKeyChecking", "no");
		} else {
			InputStream streamKnownHosts = Core.getFileDocumentContent(context, sftpConfiguration.getSFTPConfiguration_KnownHosts().getMendixObject());
			jsch.setKnownHosts(streamKnownHosts);
		}

		if (!(authenticationType == AuthenticationType.Username_and_password)) {
			jsch.addIdentity(user, privateKey, null, passPhrase);
		}
		
		Session session = jsch.getSession(user, host, port);
		if (password != null && password != "") {
			session.setPassword(password);
		}

		session.setConfig(config);
		return session;
		} 
	
	public static Boolean closeSFTPChannel(Session session, ChannelSftp sftpChannel) {
		sftpChannel.exit();
				
		return true;
	}

	private static void DisconnectSession(Session session) {
		// TODO Auto-generated method stub
		session.disconnect();
	}

	//debug code
	public static void printKnownHosts(JSch jsch) {

	}
	
	//validation should occur in the calling microflow
	public static Boolean getFileDocumentFromSFTP(SFTPConfiguration sftpConfiguration, FileDocument fileDocument, IContext context) throws CoreException, JSchException, IOException {
		String remoteSource = sftpConfiguration.getRemoteSourceFolder(context);
		Boolean keepRemoteFile = sftpConfiguration.getKeepRemoteFile(context);
		String fileName = "";
		if (fileDocument != null) {
			fileName = fileDocument.getName();
		}
		Session session = createSession(sftpConfiguration, context);
		ChannelSftp sftpChannel = createSFTPChannel(session);
		InputStream in;
		try {
			in = sftpChannel.get(remoteSource + fileName);
			Core.storeFileDocumentContent(context,
					fileDocument.getMendixObject(), in);
			in.close();
			if (!keepRemoteFile)
				sftpChannel.rm(remoteSource + fileName); // remove file from
															// destination
			return true;
			
		} catch (SftpException e) {
			throw new MendixRuntimeException(
					"SftpException occured for document " + fileName
							+ " with action Get" + ".", e);
		} catch (IOException e) {
			throw new MendixRuntimeException(
					"IOException occured for document " + fileName
							+ " with action Get" + ".", e);
		} finally {
			closeSFTPChannel(session, sftpChannel);
		}
	}
	
	//validation should occur in the calling microflow
	public static Boolean sendFileDocumentToSFTP(SFTPConfiguration sftpConfiguration, FileDocument fileDocument, IContext context) throws CoreException, JSchException, IOException {
		String remoteDestination = sftpConfiguration.getRemoteDestinationFolder(context);
		String fileName = "";
		if (fileDocument != null) {
			fileName = fileDocument.getName();
		}

		Session session = createSession(sftpConfiguration, context);
		ChannelSftp sftpChannel = createSFTPChannel(session);

		try {
			InputStream out = Core.getFileDocumentContent(context, fileDocument.getMendixObject());
			sftpChannel.put(out, remoteDestination + fileName);
			return true;

		} catch (SftpException e) {
			throw new MendixRuntimeException(
					"SftpException occured for document " + fileName
							+ " with action Send" + ".", e);
		} finally {
			closeSFTPChannel(session, sftpChannel);
		}
	}
	
	//validation should occur in the calling microflow
	public static ArrayList<IMendixObject> getFileListFromSFTP(SFTPConfiguration sftpConfiguration, IContext context) throws CoreException, JSchException, IOException {
		ArrayList<IMendixObject> SFTPFileDocumentList = new ArrayList<IMendixObject>();
		String remoteSource = sftpConfiguration.getRemoteSourceFolder(context);
		
		Session session = createSession(sftpConfiguration, context);
		session.connect();
		ChannelSftp sftpChannel = createSFTPChannel(session);

		try {
			@SuppressWarnings("rawtypes")
			Vector fileList = sftpChannel.ls(remoteSource);
			for (int i = 0; i < fileList.size(); i++) {
				Object o = fileList.get(i);
				// make sure we have list entries
				if (o instanceof LsEntry) {
					LsEntry entry = (LsEntry) o;
					SftpATTRS attribs = entry.getAttrs();
					// only go for the files
					if (!attribs.isDir()) {
						SFTPFileDocument newFileDoc = new SFTPFileDocument(context);
						newFileDoc.setDirectory(context, remoteSource);
						newFileDoc.setName(context, entry.getFilename());
						SimpleDateFormat df = new SimpleDateFormat("EEE MMM dd hh:mm:ss z yyyy", Locale.US);
						newFileDoc.setLastModificationDate(context, df.parse(attribs.getMtimeString(), new ParsePosition(0)));
						newFileDoc.commit(context);
						SFTPFileDocumentList.add(newFileDoc.getMendixObject());
					}
				}
			}
			return SFTPFileDocumentList;
		} catch (SftpException e) {
			throw new MendixRuntimeException(
					"SftpException occured when retrieving file list" + ".", e);
		} catch (CoreException e) {
			throw new MendixRuntimeException("CoreException occurred when retrieving file list", e);
		} finally {
			closeSFTPChannel(session, sftpChannel);
		}

	}

	//set up an unvalidated connection to get the host key and fingerprint
	//and save them for a user to validate
	//validation should occur in the calling microflow
	public static Boolean setKnownHosts(SFTPConfiguration sftpConfiguration, IContext context) throws CoreException, JSchException, IOException {
	//create session
	JSch jsch = new JSch();
	java.util.Properties config = new java.util.Properties();
	config.put("StrictHostKeyChecking", "no"); //since we have no known hosts, host key checking has to be disabled.
	byte[] privateKey = getBytesPrivateKey(sftpConfiguration, context);
	byte[] passPhrase = getBytesPassPhrase(sftpConfiguration, context); 
	
	if (!(sftpConfiguration.getAuthenticationType() == AuthenticationType.Username_and_password)) {
		jsch.addIdentity(sftpConfiguration.getUsername(), privateKey, null, passPhrase);
	}	
	Session session = jsch.getSession(sftpConfiguration.getUsername(), sftpConfiguration.getHostname(), sftpConfiguration.getPort());
	String password = sftpConfiguration.getPassword();
	if (password != null && password != "") {
		session.setPassword(password);
	}
	session.setConfig(config);
	
	try {
		//connect to the host and get the host key and fingerprint
		session.connect();
		HostKey hostKey = session.getHostKey();
		String knownHostsContent = hostKey.getHost() + " " + hostKey.getType() + " " + hostKey.getKey();
		String knownHostsFingerprint = hostKey.getFingerPrint(jsch);

		//save the data to the knownHostsFile
		InputStream knownHostsStream = new ByteArrayInputStream(knownHostsContent.getBytes(StandardCharsets.UTF_8));
		KnownHosts knownHostsFile = sftpConfiguration.getSFTPConfiguration_KnownHosts();
		Core.storeFileDocumentContent(context, knownHostsFile.getMendixObject(), knownHostsStream);
		knownHostsFile.setFingerprint(knownHostsFingerprint);
		Core.commitWithoutEvents(context, knownHostsFile.getMendixObject());
		return true;
	} 	catch (JSchException e) {
			throw new MendixRuntimeException("JschException occured when opening sftpSession" + ".", e);
		} finally {
			session.disconnect();
		}
	}

	//Generate a key pair and save them in the passed FileDocuments. 
	//If a pass phrase has been set, encrypt the private key with it, and save the pass phrase
	public static Boolean generateKeyPair(PrivateKey privateKey, PublicKey publicKey, PassPhraseEntry passPhraseEntry, IContext context) throws CoreException, IOException, JSchException {
	if (publicKey == null) {
		throw new MendixRuntimeException("Parameter publicKey is empty");
	}
	
	if (privateKey == null) {
		throw new MendixRuntimeException("Parameter privateKey is empty");
	}

	if (passPhraseEntry == null) {
		throw new MendixRuntimeException("Parameter passPhraseEntry is empty");
	}
	//currently hard coded, choice based on expected compatibility and longevity		
	int keySize = 2048;
	int type = KeyPair.RSA;
	String passphrase = "";
	if (!(passPhraseEntry.getPassPhraseInput() == null)) { 
		passphrase = passPhraseEntry.getPassPhraseInput();
	}
	String comment = ""; //not used
		
	//Generate the key pair
	JSch jsch=new JSch();
	KeyPair keyPair=KeyPair.genKeyPair(jsch, type, keySize);
	
	//write the keys to temporary file:
	//Jsch returns an OutputStream, but Mendix requires an InputStream
	String temporaryFilePath = Core.getConfiguration().getTempPath().getAbsolutePath();
	String tempPrivateKeyFile = temporaryFilePath + "\\tempPrivateKey.tmp";
	if (passphrase == "") {
		keyPair.writePrivateKey(tempPrivateKeyFile);
	} else{
		byte[] passphraseBytes = passphrase.getBytes(StandardCharsets.UTF_8);
		keyPair.writePrivateKey(tempPrivateKeyFile, passphraseBytes);
		privateKey.setPassPhrase(passphrase);
	}
	String tempPublicKeyFile = temporaryFilePath + "\\tempPublicKey.tmp";
	keyPair.writePublicKey(tempPublicKeyFile, comment);
	keyPair.dispose();
	    
	//write the private key to the passed FileDocument
	File filePrivateKey = new java.io.File(tempPrivateKeyFile);
	FileInputStream streamPrivateKey = new java.io.FileInputStream( tempPrivateKeyFile );
	Core.storeFileDocumentContent(context, privateKey.getMendixObject(), streamPrivateKey);
	streamPrivateKey.close();
	privateKey.setName("privatekey.priv");
	
	Core.commitWithoutEvents(context, privateKey.getMendixObject());
	filePrivateKey.delete();
	    
	//write the public key to the passed FileDocument
	File filePublicKey = new java.io.File(tempPublicKeyFile);
	FileInputStream streamPublicKey = new java.io.FileInputStream( tempPublicKeyFile );
	Core.storeFileDocumentContent(context, publicKey.getMendixObject(), streamPublicKey);
	streamPublicKey.close();
	publicKey.setName("publicKey.pub");
	Core.commitWithoutEvents(context, publicKey.getMendixObject());
	filePublicKey.delete();
	
	return true;
	}
	
	public static class MendixLogger implements com.jcraft.jsch.Logger {

			
		@Override
		public boolean isEnabled(int arg0) {
			return true;
		}

		@Override
		public void log(int level, String message) {
			switch (level) {
			case DEBUG:
				logger.trace(message);
				break;
			case INFO:
				logger.debug(message);
				break;
			case WARN:
				logger.warn(message);
				break;
			case ERROR:
				logger.error(message);
				break;
			case FATAL:
				logger.critical(message);
				break;
			}
		}
		
	}
}
