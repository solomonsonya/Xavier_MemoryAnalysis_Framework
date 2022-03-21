/**
 * @author Solomon Sonya
 */


package Driver;

import java.security.*;
import java.io.*;
import java.math.*;
import java.nio.charset.*;
import java.text.*;
import java.util.*;
import java.sql.Connection;

import javax.crypto.*;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

public class Hash 
{
	public static final String VERSION = "1.1";
	
	public static final String myClassName = "Hash";
	public Driver driver = new Driver();
	Time time = new Time();
	
	
	//
	//HASH ALGORITHMS
	//
	public static final String MD5 = "MD5";
	public static final String SHA_1 = "SHA-1";
	public static final String SHA_256 = "SHA-256";	
	public static final String SHA_512 = "SHA-512";

	
	
	public Hash(){}	
	
	/**
	 * 	Hash.hash_file(fle, Hash.SHA_256, 32));
	 * 
	 * Signature returned is Base64 encoded representation of signature byte array
	 * @param fleToSign
	 * @param privateKey
	 * @return
	 */
	public String hash_file(File fleToHash, String hash_algorithm, int minHashLengthToPad, boolean encodeHash_in_base64, boolean verbose)
	{
		try
		{
			if(fleToHash == null)
			{
				
				return null;
			}
			
			long startTime = time.getTime_Current_Millis();
			
			if(verbose)
				driver.sop("Commencing hash " + hash_algorithm + "] generation on " + fleToHash.getCanonicalPath());
			
			//Source: http://docs.oracle.com/javase/tutorial/security/apisign/step3.html
			//specify message signature algorithm and security provider
			MessageDigest messageDigest = MessageDigest.getInstance(hash_algorithm);
			try	{	messageDigest.reset();	} catch(Exception e){}
			
			//initialize signature object with private key
			//signature.initSign(keyPair.getPrivate());
						
			//initialize output for the user
			//IncrementObject steps = new IncrementObject(fleToSign.length()/1024.00);
			
			//read in the file, and update the signature during each iteration of the buffer read
			FileInputStream fis = new FileInputStream(fleToHash);
			BufferedInputStream brIn = new BufferedInputStream(fis);
			byte[] buffer = new byte[1024];
			int len;
			
			
			if(verbose)
				driver.sp("[" + time.getTimeStamp_Without_Date() + "]\t" + "Calculating hash now...");
			
			
			while ((len = brIn.read(buffer)) >= 0) 
			{
				messageDigest.update(buffer, 0, len);
			    //driver.sp(".");
			    
			}
			
			if(verbose)
				driver.sp("Done!\n");
			
			//finished reading, close the file
			try{	brIn.close();	}	catch(Exception e){}
			try{	fis.close();	}	catch(Exception e){}
			
			//
			//With all data updated, compute HASH
			//
			byte[] digest = messageDigest.digest(); //<---- this is the message digest in byte form!
			
			//convert digest into padded value
			
			//at this point, if we were using sha-1 (160 bit), we have a 20 byte long key, represented in Hex as a 40 dig long string (bcs each nibble is shown below ==> 2 nibbles per each byte)
			//hwever, sha-1 was shown to have a collision in 2^61 bit complexity. 
			
			//therefore, we opted for SHA-256 (256 bit == 32 byte) hashing algorithm, because no known/published collision attacks have been reported yet
			//The output will return a 64 char long string (bcs we require 2 hex chars per byte)
			//So in a 256 bit hash output, 2^256 == 1.16 e77 different possibilities. Yes, our doc ID is pretty unique!
			
			//SHA-512 giv es us a 512 bit == 64 byte hash value.  The result of the hash algorithm will return a string of 128
			//so in 512 bit hash output, 2^512 == 1.34 e154 different possibilities... collisions are extremely rare in this case!
			
			if(encodeHash_in_base64)
			{
				return new String(Base64.encode(digest));
			}
			
			//
			//convert the digest array into a hex string to display it to the user, OR choose to BASE64ENCODE  the digest array as well
			//
			BigInteger bigInt_Hash = new BigInteger(1, digest);
			String hash = bigInt_Hash.toString(16); //state to use HEX
			
			//
			//Base64 Encode Hash
			//
			//String base64encode_HASH = Drivers.getBase64EncodedText_From_ByteArray(digest);
			
			//pad so that hash is min char len
			for(int i = hash.length(); i < minHashLengthToPad; i++)
			{
				hash = "0" + hash;
			}
			
			return hash;
			
			
		}
		catch(Exception e)
		{
			driver.eop("hash_file",  myClassName,  e, false);
			
		}
		
		
		
		return null;
	}
	
	/**
	 * 
	 */
	public String hash_message(String messageToHash, String HashAlgorithm, int minHashLengthToPad, boolean encodeHash_in_base64)
	{
		try
		{			
			//http://stackoverflow.com/questions/415953/generate-md5-hash-in-java
			
			byte[] message = messageToHash.getBytes("UTF-8");
			MessageDigest messageDigest = MessageDigest.getInstance(HashAlgorithm);
			messageDigest.update(message);
			
			byte[] digest = messageDigest.digest(); //<---- this is the message digest in byte form!
			
			//Right now, we will take the message, hash it , and return a Base64 encoded message representing the original message so that it can be transferred across the socket while preserving the contents of the binary data from the hash
			if(encodeHash_in_base64)
			{
				//convert the byte array of the digest into a base64 encoded string
				String base64_Hash = new String(Base64.encode(digest));
				
				return base64_Hash;
			}
			
			//else, produce MD5 byte hash	
						
			BigInteger bigInt_Hash = new BigInteger(1, digest);
			String hash = bigInt_Hash.toString(16);
			
			//pad so that hash is 32 char's long
			for(int i = hash.length(); i < minHashLengthToPad; i++)
			{
				hash = "0" + hash;
			}
			
			return hash;
			
		}
		catch(Exception e)
		{
			driver.eop("hashMessage", myClassName, e, false);
		}
		
		return " ";
	}
	
	/**
	 * Return Base64 encoded string of the message hashed in MD5
	 * This is to be easier to transmit the encoding of the message to detect malicious altering while in transit
	 * 
	 * hashLength only applies to non-base 64 encoded data
	 * 
	 * @param messageToHash
	 * @return
	 */
	public String hashMessage_MD5(String messageToHash, int minHashLengthToPad, boolean encodeHash_in_base64)
	{
		try
		{			
			
			//Right now, we will take the message, hash it , and return a Base64 encoded message representing the original message so that it can be transferred across the socket while preserving the contents of the binary data from the hash
			if(encodeHash_in_base64)
			{
				byte[] message = messageToHash.getBytes();
				MessageDigest messageDigest = MessageDigest.getInstance("MD5");
				messageDigest.update(message);
				
				byte[] digest = messageDigest.digest(); //<---- this is the message digest in byte form!
				
				//convert the byte array of the digest into a base64 encoded string
				String base64_Hash = new String(Base64.encode(digest));
				
				return base64_Hash;
			}
			
			//else, produce MD5 byte hash	
			//http://stackoverflow.com/questions/415953/generate-md5-hash-in-java		
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			messageDigest.update(messageToHash.getBytes());			
			
			byte[] digest = messageDigest.digest(); //<---- this is the message digest in byte form!
			
			BigInteger bigInt_Hash = new BigInteger(1, digest);
			String hash = bigInt_Hash.toString(16);
			
			//pad so that hash is 32 char's long
			for(int i = hash.length(); i < minHashLengthToPad; i++)
			{
				hash = "0" + hash;
			}
			
			return hash;
			
		}
		catch(Exception e)
		{
			driver.eop("hashMessage_MD5", myClassName, e, false);
		}
		
		return " ";
	}
	
	public String hash_message(ArrayList<String>alData, String hashAlgorighm, int minHashLengthToPad, boolean encodeHash_in_base64)
	{
		try
		{
			//Right now, we will take the message, hash it , and return a Base64 encoded message representing the original message so that it can be transferred across the socket while preserving the contents of the binary data from the hash
			//MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
			MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorighm);
			
			byte [] token = null;
			//
			//Update Hash until complete
			//
			for(int i = 0; i < alData.size(); i++)
			{
				try
				{
					//
					//Grab value to be hashed
					//
					token = alData.get(i).trim().getBytes("UTF-8");
					
					//
					//Update Hash
					//
					messageDigest.update(token);
				}
				catch(Exception ee)
				{
					continue;
				}
				
			}//end for
			
			//
			//With all data updated, compute HASH
			//
			byte[] digest = messageDigest.digest(); //<---- this is the message digest in byte form!
			
			//convert digest into padded value
			
			//at this point, if we were using sha-1 (160 bit), we have a 20 byte long key, represented in Hex as a 40 dig long string (bcs each nibble is shown below ==> 2 nibbles per each byte)
			//hwever, sha-1 was shown to have a collision in 2^61 bit complexity. 
			
			//therefore, we opted for SHA-256 (256 bit == 32 byte) hashing algorithm, because no known/published collision attacks have been reported yet
			//The output will return a 64 char long string (bcs we require 2 hex chars per byte)
			//So in a 256 bit hash output, 2^256 == 1.16 e77 different possibilities. Yes, our doc ID is pretty unique!
			
			//SHA-512 giv es us a 512 bit == 64 byte hash value.  The result of the hash algorithm will return a string of 128
			//so in 512 bit hash output, 2^512 == 1.34 e154 different possibilities... collisions are extremely rare in this case!
			
			if(encodeHash_in_base64)
			{
				//convert the byte array of the digest into a base64 encoded string
				return new String(Base64.encode(digest));
			}
			
			//
			//convert the digest array into a hex string to display it to the user, OR choose to BASE64ENCODE  the digest array as well
			//
			BigInteger bigInt_Hash = new BigInteger(1, digest);
			String hash = bigInt_Hash.toString(16); //state to use HEX
		
			//pad so that hash is min char len
			for(int i = hash.length(); i < minHashLengthToPad; i++)
			{
				hash = "0" + hash;
			}
			
			return hash;
			
		}
		catch(Exception e)
		{
			driver.eop("hash_message with arraylist<String>", myClassName, e, false);			
		}
		
		return "" + time.getTime_Current_Millis();				
	}
	
}
