/**
 * Container to house certain information regarding a file
 * 
 * @author Solomon Sonya
 */

package Driver;

import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.attribute.*;
import java.io.*;

public class FileAttributeData 
{
	public static final String myClassName = "FileAttributeData";
	public static Driver driver = new Driver();
	
	BasicFileAttributeView basic_file_attr_view = null;
	BasicFileAttributes  attr = null;

	public volatile File fle = null;
	public boolean is_file = false;
	public boolean is_directory = false;
	
	
	
	/**actual file size in bytes*/
	public long length = 0;
	
	/**converted file size length to return e.g. 28.5 GBs, etc*/
	public String size = "0";
	
	public String file_name = "unspecified";
	public String creation_date = "unspecified";
	public String last_accessed = "unspecified";
	public String last_modified = "unspecified";
	
	public volatile Hash hash = new Hash();
	public volatile String hash_md5 = null;
	public volatile String hash_sha256 = null;
	public volatile boolean  is_hashing_complete = false; 
	
	private volatile String attributes = "not specified";
	
	public FileAttributeData(File file)
	{
		try
		{
			fle = file;
			enumerate_file(file);			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public FileAttributeData(File file, boolean hash_file, boolean hash_file_in_separate_execution_thread)
	{
		try
		{
			fle = file;
			enumerate_file(file);		
			
			if(hash_file)
				this.set_hash(hash_file_in_separate_execution_thread);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	public boolean enumerate_file(File fle)
	{
		try
		{
			if(fle == null || !fle.exists())
				return false;
			
			is_file = fle.isFile();
			is_directory = fle.isDirectory();
						
			
			try
			{
				basic_file_attr_view    = Files.getFileAttributeView(FileSystems.getDefault().getPath(fle.getCanonicalPath()), BasicFileAttributeView.class);
				attr     				= basic_file_attr_view.readAttributes();
				
				creation_date = driver.getTime_Specified_Hyphenated_with_seconds_using_colon(attr.creationTime().toMillis());
				last_accessed = driver.getTime_Specified_Hyphenated_with_seconds_using_colon(attr.lastAccessTime().toMillis());
				last_modified = driver.getTime_Specified_Hyphenated_with_seconds_using_colon(attr.lastModifiedTime().toMillis());
				length = attr.size();
				file_name = fle.getName();
				
				this.size = driver.get_file_size(length);
			}
			catch(Exception ee){}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "enumerate_file", e);
		}
		
		return false;
	}
	
	public String get_attributes(String delimiter)
	{
		try		
		{
			attributes = "File Name: " + file_name + delimiter + 
						 "File Size: " + size + delimiter + 
						 "Creation Date: " + creation_date + delimiter + 
						 "Last Accessed: " + last_accessed + delimiter +
						 "Last Modified: " + last_modified;
			
			if(this.hash_md5 != null && this.hash_md5.trim().length() > 0)
				attributes = attributes + delimiter + "MD5: " + hash_md5;
			
			if(this.hash_sha256 != null && this.hash_sha256.trim().length() > 0)
				attributes = attributes + delimiter + "SHA-256: " + hash_sha256;
			
			return  attributes;
					
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_attributes", e);
		}
		
		return "";
	}
	
	public String get_name_size_hash(String delimiter)
	{
		try		
		{
			attributes = "File Name: " + file_name + delimiter + 
						 "File Size: " + size + delimiter;// + 
						 //"Creation Date: " + creation_date + delimiter + 
						// "Last Accessed: " + last_accessed + delimiter +
						 //"Last Modified: " + last_modified;
			
			if(this.hash_md5 != null && this.hash_md5.trim().length() > 0)
				attributes = attributes + delimiter + "MD5: " + hash_md5;
			
			if(this.hash_sha256 != null && this.hash_sha256.trim().length() > 0)
				attributes = attributes + delimiter + "SHA-256: " + hash_sha256;
			
			return  attributes;
					
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_name_size_hash", e);
		}
		
		return "";
	}
	
	
	public String set_hash(boolean execute_in_separate_thread)
	{
		try
		{
			if(execute_in_separate_thread)
			{
				new Thread(new Runnable() 
				{
				     public void run() 
				     {
				    	 hash_md5 = hash.hash_file(fle, Hash.MD5, 32, false, false);
				    	 
				    	 //driver.sop("MD5 hash for " + fle + " --> " + hash_md5);
				    	 
				    	 if(hash_sha256 != null && !hash_sha256.equals(""))
				    		 is_hashing_complete = true;
				     }
				}).start();
				
				new Thread(new Runnable() 
				{
				     public void run() 
				     {
				    	 hash_sha256 = hash.hash_file(fle, Hash.SHA_256, -1, false, false);
				    	 
				    	 if(hash_md5 != null && !hash_md5.equals(""))
				    		 is_hashing_complete = true;
				    	 
				    	 //driver.sop("SHA256 hash for " + fle + " --> " + hash_sha256);
				     }
				}).start();
			}
			
			else//serial
			{
				 hash_md5 = hash.hash_file(fle, Hash.MD5, 32, false, false);		    	 
		    	 //driver.sop("MD5 hash for " + fle + " --> " + hash_md5);
		    	 
		    	 hash_sha256 = hash.hash_file(fle, Hash.SHA_256, -1, false, false);		    	 
		    	 //driver.sop("SHA256 hash for " + fle + " --> " + hash_sha256);
		    	 
		    	 is_hashing_complete = true;
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_hash", e);
		}
		
		return "";
	}
	
	/*public String get_hash(boolean execute_in_separate_thread)
	{
		try
		{
			if(execute_in_separate_thread)
			{
				new Thread(new Runnable() 
				{
				     public void run() 
				     {
				          hash = new 
				     }
				}).start();
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_hash", e);
		}
		
		return "";
	}*/
	
}
