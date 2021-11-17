/**
 * @author Solomon Sonya
 * */

package Encryption;


import java.security.MessageDigest;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.xml.bind.*;

public class Encryption 
{
	public static final String myClassName = "Encryption";
	
	MessageDigest messageDigest = null;
	public volatile String key = "";
	
	
	public volatile String iv_value = "";
	public IvParameterSpec iv = null;
    SecretKeySpec secret_key_spec = null;
    Cipher cipher_ENCRYPT = null;
    Cipher cipher_DECRYPT = null;
    
    public static final String default_iv_value = "solomonsonya";
    
    public static volatile boolean ENCRYPTION_ENABLED = true;
   
	
	public Encryption(String KEY, String init_vector_value)
	{
		try
		{
			key = KEY;
			iv_value = init_vector_value;
			configure_encryption(key, iv_value);									
		}
		catch(Exception e)
		{
			eop("Constructor - 1");
		}
	}
	
	public boolean configure_encryption(String key_encryption, String initialization_vector)
	{
		try
		{
			//specify a key of 128 bits in length. To do so, let's hash the key, then take the first 16 bytes and use this as the key:
			String key_hash = this.hash_sha256(key_encryption);
			String iv_hash = this.hash_sha256(initialization_vector);
			
			iv = new IvParameterSpec(iv_hash.substring(0,16).getBytes("UTF-8"));
			secret_key_spec = new SecretKeySpec(key_hash.substring(0,16).getBytes("UTF-8"), "AES");
			
			//ENCRYPTION CIPHER
			cipher_ENCRYPT = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher_ENCRYPT.init(Cipher.ENCRYPT_MODE, secret_key_spec, iv);	
			
			//DECRYPTION CIPHER
			cipher_DECRYPT = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher_DECRYPT.init(Cipher.DECRYPT_MODE, secret_key_spec, iv);	
			
			sop("\nEncryption key set to -->" + key_encryption);
			
			ENCRYPTION_ENABLED = true;
			return true;
		}
		catch(Exception e)
		{
			eop("configure_encryption", e);
		}
		
		return false;
	}
	
	/**
	 * return base64 encrypted text
	 */
	public String encrypt(String text)
	{
		try
		{
			return BASE64_ENCODE(cipher_ENCRYPT.doFinal(text.getBytes("UTF-8")));
		}
		catch(Exception e)
		{
			eop("encrypt");
		}
		
		return text;
	}
	
	/**
	 * pass in the encrypted text as base64 encoded string
	 */
	public String decrypt(String text)
	{
		try
		{
			return new String(cipher_DECRYPT.doFinal(this.BASE64_DECODE_RETURN_BYTE_ARRAY(text)), "UTF-8");
		}		
		catch(IllegalBlockSizeException ibse)
		{
			//likely a result that the text is not indeed encyrpted, return the original text!
			return text;
		}	
		catch(BadPaddingException bpe)
		{
			//likely a result that the 2 encryption keys are incorrect
			sop("Error! I can not decrypt received line. Have the encyrption keys changed???");		
			sop("Received line -->" + text);
		}
		catch(IllegalArgumentException ie)
		{
			//likely a result that the 2 encryption keys are incorrect
			sop("Error! I can not decrypt received line. Has the distant end removed encryption???");		
			sop("Received line -->" + text);
		}
		catch(Exception e)
		{
			eop("decrypt", e);
		}
		
		
		
		return text;
	}
	
	public String BASE64_ENCODE(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return line;
			
			return DatatypeConverter.printBase64Binary(line.getBytes("UTF-8"));
		}
		catch(Exception e)
		{
			eop("BASE64_ENCODE");
		}
		
		return line;
	}
	
	public String BASE64_ENCODE(byte [] array)
	{
		try
		{
			if(array == null)
				return "";
			
			return DatatypeConverter.printBase64Binary(array);
		}
		catch(Exception e)
		{
			eop("BASE64_ENCODE");
		}
		
		return "";
	}
	
	public String BASE64_DECODE(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return line;
			
			return new String(DatatypeConverter.parseBase64Binary(line), "UTF-8");
		}
		catch(Exception e)
		{
			eop("BASE64_DECODE");
		}
		
		return line;
	}
	
	public byte [] BASE64_DECODE_RETURN_BYTE_ARRAY(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return null;
			
			return DatatypeConverter.parseBase64Binary(line);
		}
		catch(Exception e)
		{
			eop("BASE64_DECODE");
		}
		
		return null;
	}
	
	public boolean eop(String mtdName)
	{
		try	{	sop("\nException handled in " + mtdName + " mtd in class: " + myClassName);	}	catch(Exception e){}
		return true;
	}
	
	public boolean eop(String mtdName, Exception e)
	{
		try	{	sop("\nException handled in " + mtdName + " mtd in class: " + myClassName + " Message Name: " + e.getLocalizedMessage());	e.printStackTrace(System.out);}	catch(Exception ee){}
		return true;
	}
	
	
	public void sop(String out) 
	{
		try	{	System.out.println(out);	}	catch(Exception e){}				
	}
	
	public void sp(String out) 
	{
		try	{	System.out.print(out);	}	catch(Exception e){}
	}
	
	public String hash_sha256(String strToHash) throws Exception {	return this.sha256Hash(strToHash);	}
	
	public String sha256Hash(String strToHash)
	{
		try
		{
			if(this.messageDigest == null)
				try	{	messageDigest = MessageDigest.getInstance("SHA-256");	}	catch(Exception e){sop("ERROR!!!! CAN NOT SET SHA CRYPTO HASH!");}
			
			/*byte[] hash = messageDigest.digest("123".getBytes("UTF-8"));
			String code = Base64.encodeBase64String(hash);
			String code2 = this.hexBytesToString(hash);*/
			
			if(strToHash == null || strToHash.trim().equals(""))
				return "empty";
			
			return this.hexBytesToString(messageDigest.digest(strToHash.getBytes("UTF-8")));						
		}
		catch(Exception e)
		{
			eop("sha256Hash");
		}
		
		return "invalid2";
	}
	
	public String hexBytesToString(byte [] bytes)
	{
		try
		{
			//special thanks to http://stackoverflow.com/questions/5531455/how-to-hash-some-string-with-sha256-in-java
			
			StringBuffer buffer = new StringBuffer();
			
			for (int i = 0; i < bytes.length; i++) 
			{
	            String hex = Integer.toHexString(0xff & bytes[i]);
	            if(hex.length() == 1) buffer.append('0');
	            buffer.append(hex);
	        }
			
			return buffer.toString();
		}
		catch(Exception e)
		{
			eop("hexBytesToString");
		}
		
		return "invalid";
	}
}
