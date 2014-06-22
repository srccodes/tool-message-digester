package com.srccodes.tools.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;



/**
 * This class contains utility methods to calculate message digest of a string using Message Digest algorithms available in Bouncy Castle.
 * 
 * @author Abhijit Ghosh
 * @version 1.0
 */
public class MessageDigester {
	private static final String SECURITY_PROVIDER_BOUNCY_CASTLE = "BC";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	/**
	 * To get Message Digest of the supplied input string using the supplied algorithm.
	 * 
	 * @param algorithm
	 * @param message
	 * @return Message Digest of the supplied input string
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public String getDigest(String algorithm, String message) throws NoSuchAlgorithmException, NoSuchProviderException {
		 MessageDigest messageDigest = MessageDigest.getInstance(algorithm, SECURITY_PROVIDER_BOUNCY_CASTLE);
		 messageDigest.reset();
		 messageDigest.update(message.getBytes());
		
		return Hex.toHexString(messageDigest.digest());
	}
	
	
	/**
	 * To get all available Message Digest algorithms for the provider
	 * 
	 * @return all available Digest Algorithms
	 */
	public List<String> getDigestAlgorithms() {
		Provider provider = Security.getProvider(SECURITY_PROVIDER_BOUNCY_CASTLE);
		List<String> algorithmList = new ArrayList<String>();
		
		for (Object keyObject : provider.keySet()) {
			String key = (String) keyObject;
			
			if (key.startsWith("MessageDigest.")) {
				String algorithm = key.substring("MessageDigest.".length());
				algorithmList.add(algorithm);
            }
		}
		
		return algorithmList;
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
		String message = "Hello SrcCodes !";
		
		MessageDigester digester =  new MessageDigester();
		List<String> allAlgorithms = digester.getDigestAlgorithms();
		System.out.println("Calculating Message Digest of '" + message + "' using all Algorithms available in Bouncy Castle");
		System.out.println("------------------------------------------------------------------------------------------------\n\n");
		for (String algorithm : allAlgorithms) { 
			System.out.println(algorithm + "-->" + digester.getDigest(algorithm, message));
		}
	}
}
