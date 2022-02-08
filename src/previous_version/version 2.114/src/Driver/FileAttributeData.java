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
import java.util.*;

import Advanced_Analysis.Node_DLL;
import Advanced_Analysis.Node_Driver;
import Advanced_Analysis.Node_Process;


public class FileAttributeData 
{
	public static final String myClassName = "FileAttributeData";
	public static Driver driver = new Driver();
	
	BasicFileAttributeView basic_file_attr_view = null;
	BasicFileAttributes  attr = null;

	public volatile File fle = null;
	public boolean is_file = false;
	public boolean is_directory = false;
	
	
	/**returned by file.length mtd*/
	public long raw_file_length = 0;
	
	/**actual file size in bytes returned by the get size of the basic file attribute*/
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
	
	public volatile String short_file_name = "unspecified";
	
	public volatile static TreeMap<String, FileAttributeData> tree_file_attributes = new TreeMap<String, FileAttributeData>();
	
	public volatile String extension = "";
	
	public volatile Node_Process process = null;
	public volatile Node_DLL DLL = null;
	
	/**driverscan, moddump, modules, modscan, driverirp, drivermodule*/
	public volatile Node_Driver module = null;
	
	public static String file_output_header = "File Name\tFile Extension\tFile Size\tMD5\tSHA-256\tPath";
	
	
	
	
	public FileAttributeData(File file, Node_Process PROCESS, Node_DLL dll)
	{
		try
		{
			fle = file;
			enumerate_file(file);	
			
			
			
			set_file_extension();
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
			
			set_file_extension();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 2", e);
		}
	}
	
	public FileAttributeData(Node_Process PROCESS)
	{
		try
		{
			this.process = PROCESS;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 3", e);
		}
	}
	
	public FileAttributeData(Node_Driver module)
	{
		try
		{
			this.module = module;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 4", e);
		}
	}
	
	/**
	 * called from import_manifest
	 * @param arr
	 */
	public FileAttributeData(String [] arr, int starting_index)
	{
		try
		{
			import_data(arr, starting_index);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 5", e);
		}
	}
	
	public boolean import_data(String []arr, int starting_index)
	{
		try
		{
			if(arr == null || arr.length < 1)
			{
				driver.directive("PUNT! empty array received. I am unable to process data import!");
				return false;
			}
			
			String key = "", value = "";
			
			for(int i = starting_index; i < arr.length; i+=2)
			{
				try
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					if(key.startsWith("file_name"))					{	file_name = value;	try	{	this.tree_file_attributes.put(file_name, this);	} catch(Exception e){}	}
					else if(key.startsWith("size"))						size = value;
					else if(key.startsWith("creation"))					creation_date = value;
					else if(key.startsWith("last_access"))				last_accessed = value;
					else if(key.startsWith("last_modified"))			last_modified = value;
					else if(key.startsWith("md5"))						hash_md5 = value;
					else if(key.startsWith("sha256"))				{	hash_sha256 = value;	this.is_hashing_complete = true;	}
					
					else if(key.startsWith("raw_file_length"))	try	{	raw_file_length = Long.parseLong(value.trim());	} catch(Exception e){driver.directive("NOTE: I was unable to parse key raw_file_length: [" + value + "]");}
					else if(key.startsWith("length"))			try	{	length = Long.parseLong(value.trim());	} catch(Exception e){driver.directive("NOTE: I was unable to parse key length: [" + value + "]");} 
					else if(key.startsWith("size"))						size = value;
					else if(key.startsWith("is_hashing_complete"))	try	{	is_hashing_complete = Boolean.parseBoolean(value.trim());	}	catch(Exception e){driver.directive("NOTE: I was unable to parse key is_hashing_complete: [" + value + "]");}
					else if(key.startsWith("attributes"))				attributes = value;
					else if(key.startsWith("short_file_name"))			short_file_name = value;
					else if(key.startsWith("extension"))				extension = value;
										
					else {	driver.directive("Unknown key [" + key + "] in importing_data mtd in " + this.myClassName);	}
				}
				catch(Exception e)
				{
					driver.directive("Error importing data in " + this.myClassName + " import_data mtd");
					continue;
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_data", e);
		}

		return false;
	}
	
	public boolean set_file_extension()
	{
		try
		{
			extension = driver.getFileExtension(fle, true);
			
			if(fle.getCanonicalPath().toLowerCase().trim().endsWith("exe") || fle.getCanonicalPath().toLowerCase().trim().contains(".exe"))
				extension = "exe";
			else if(fle.getCanonicalPath().toLowerCase().trim().endsWith("dll")|| fle.getCanonicalPath().toLowerCase().trim().contains(".dll"))
				extension = "dll";
			else if(fle.getCanonicalPath().toLowerCase().trim().endsWith("drv")|| fle.getCanonicalPath().toLowerCase().trim().contains(".drv"))
				extension = "drv";
			else if(fle.getCanonicalPath().toLowerCase().trim().endsWith("cpl")|| fle.getCanonicalPath().toLowerCase().trim().contains(".cpl"))
				extension = "cpl";
						
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_file_extension", e);
		}
		
		return false;
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
				raw_file_length = fle.length();
				file_name = fle.getName();
				 
				this.size = driver.get_file_size(length);
				
				try	{	this.tree_file_attributes.put(file_name, this);	} catch(Exception e){}
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
	
	public boolean duplicate_attributes(FileAttributeData src_attr, FileAttributeData dst_attr)
	{
		try
		{
			dst_attr.hash_md5 = src_attr.hash_md5;
			dst_attr.hash_sha256 = src_attr.hash_sha256;
			
			this.is_hashing_complete = true;
									
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "duplicate_attributes", e);
		}
		
		return false;
	}
	
	public String set_hash(boolean execute_in_separate_thread)
	{
		if(fle == null || !fle.exists())
			return null;
		
		//
		//determine if we have seen this request before
		//
		try
		{
			if(tree_file_attributes.containsKey(fle.getCanonicalPath().trim()))
			{
				FileAttributeData attr = tree_file_attributes.get(fle.getCanonicalPath().trim());
						
				if(attr.raw_file_length == fle.length())
				{
					if(duplicate_attributes(attr, this))
						return "";					
				}
				
			}
			
		}
		catch(Exception e){}
		
		
		//
		//Conduct the file hash
		//
		try
		{
			if(execute_in_separate_thread)
			{
				FileAttributeData me = this;
				
				new Thread(new Runnable() 
				{
				     public void run() 
				     {
				    	 hash_md5 = hash.hash_file(fle, Hash.MD5, 32, false, false);
				    	 
				    	 //driver.sop("MD5 hash for " + fle + " --> " + hash_md5);
				    	 
				    	 if(hash_sha256 != null && !hash_sha256.equals(""))
				    	 {
				    		 is_hashing_complete = true;
				    		 
				    		 //store update in the tree
				    		 if(fle != null && fle.exists())
				    		 {
				    			 try
				    			 {
				    				 tree_file_attributes.put(fle.getCanonicalPath().trim(), me);	 
				    			 }
				    			 catch(Exception e)
				    			 {
				    				 //do n/t
				    			 }
				    			 
				    		 }
				    	 }
				     }
				}).start();
				
				new Thread(new Runnable() 
				{
				     public void run() 
				     {
				    	 hash_sha256 = hash.hash_file(fle, Hash.SHA_256, -1, false, false);
				    	 
				    	 if(hash_md5 != null && !hash_md5.equals(""))
				    	 {
				    		 is_hashing_complete = true;
				    		 
				    		  //store update in the tree
				    		 if(fle != null && fle.exists())
				    		 {
				    			 try
				    			 {
				    				 tree_file_attributes.put(fle.getCanonicalPath().trim(), me);	 
				    			 }
				    			 catch(Exception e)
				    			 {
				    				 //do n/t
				    			 }
				    			 
				    		 }
				    	 }
				    	 
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
		    	 
		    	 //store update in the tree
	    		 if(fle != null && fle.exists())
	    		 {
	    			 try
	    			 {
	    				 tree_file_attributes.put(fle.getCanonicalPath().trim(), this);	 
	    			 }
	    			 catch(Exception e)
	    			 {
	    				 //do n/t
	    			 }
	    			 
	    		 }
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_hash", e);
		}
		
		return "";
	}
	
	
	public String get_html_table_information()
	{
		try
		{
			return ("	<tr> <td> " + this.file_name + " </td> <td> " + size + " </td> <td> " + creation_date + " </td> <td> " + last_accessed + " </td> <td> " + last_modified + " </td> <td> " + hash_md5 + " </td> <td> " + hash_sha256 + " </td> </tr>	");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_html_table_information", e);
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
	
	
	
	
	public boolean write_node_ENTRY(String title, String value, PrintWriter pw)
	{
		try
		{
			if(value == null || value.trim().equals(""))
				return false;
					
			pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html(title + " " + value).replace("\\", "\\\\") + "\" },");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_ENTRY", e);
		}
		
		return false;
	}
	
	public boolean write_node_file_attributes(PrintWriter pw, Node_Process process, Node_DLL dll)
	{
		try
		{
			pw.println("\t\t" +  "{ \"name\": \"" + "File Attributes" + "\" , \"children\": [");
			
			FileAttributeData attrib = this;
			
			if(dll != null && process != null && process.PID > -1 && dll.tree_file_dump_attributes.containsKey(process.PID))
			{
				attrib = dll.tree_file_dump_attributes.get(process.PID);
				
				//write_node_ENTRY("File Name: ", file_name, pw);
				write_node_ENTRY("File Name: ", attrib.file_name, pw);
				write_node_ENTRY("File Size: ", attrib.size, pw);
				write_node_ENTRY("Hash [MD5]: ", attrib.hash_md5, pw);
				write_node_ENTRY("Hash [SHA-256]: ", attrib.hash_sha256, pw);
			}
			else
			{
				if(short_file_name == null || short_file_name.trim().equals("") || short_file_name.toLowerCase().equals("unspecified"))
					short_file_name = this.file_name;
				
				//write_node_ENTRY("File Name: ", file_name, pw);
				write_node_ENTRY("File Name: ", short_file_name, pw);
				write_node_ENTRY("File Size: ", size, pw);
				write_node_ENTRY("Hash [MD5]: ", hash_md5, pw);
				write_node_ENTRY("Hash [SHA-256]: ", hash_sha256, pw);
			}
			
			
			
	
			pw.println("\t\t" +  "]},");
		
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_file_attributes", e);
		}
		
		return false;
	}
	
	public String toString(String header, String delimiter, boolean split_into_2_lines)
	{
		try
		{
			String crlf = "";
			
			if(header == null)
				header = "";
			
			if(split_into_2_lines)
				crlf = "\n" + header;
			
			attributes = header + "File Name: " + file_name + delimiter + 
					 "File Size: " + size + delimiter + 
					 "Creation Date: " + creation_date + delimiter + 
					 "Last Accessed: " + last_accessed + delimiter +
					 "Last Modified: " + last_modified + delimiter;
		
			attributes = attributes + crlf;
			
		if(this.hash_md5 != null && this.hash_md5.trim().length() > 0)
			attributes = attributes + "MD5: " + hash_md5 + delimiter;
		
		if(this.hash_sha256 != null && this.hash_sha256.trim().length() > 0)
			attributes = attributes + "SHA-256: " + hash_sha256 + delimiter;
		
		return  attributes; 
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString # separated", e);
		}
		
		return this.get_attributes(delimiter);
	}
	
	public String toString(String delimiter)
	{
		try
		{
			String path = ""+fle;
			
			if(this.process != null)
				path = process.path;
			else if(this.DLL != null)
				path = DLL.path;
			
			return file_name + delimiter + extension + delimiter + size + delimiter + hash_md5 + delimiter + hash_sha256 + delimiter + path;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		return file_name + "\t" + extension + "\t" + size + "\t" + hash_md5 + "\t" + hash_sha256 + "\t" + fle;
	}
	
	
	
	public boolean write_html_table_entries(PrintWriter pw)
	{
		try
		{
			pw.print(" <td> " + driver.normalize_html(this.size).replace("\\", "&#92") + "</td>");
			pw.print(" <td> " + "<a href =\"https://www.virustotal.com/gui/file/" + driver.normalize_html(hash_sha256).replace("\\", "&#92") + "/detection\" target=\"_blank\"> Link </a></td>");
			pw.print(" <td> " + driver.normalize_html(this.hash_md5).replace("\\", "&#92") + "</td>");
			pw.print(" <td> " + driver.normalize_html(this.hash_sha256).replace("\\", "&#92") + "</td>");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_html_table_entries", e);
		}
		
		return false;
	}
	
	public boolean write_manifest_entry(PrintWriter pw, String header, String override_file_name)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(header == null || header.trim().equals(""))
				header = "file_attr\t ";
						
			if(this.raw_file_length > 0)
				pw.println(header + "raw_file_length" + ":\t " + raw_file_length);			
			
			if(this.length > 0)
				pw.println(header + "length" + ":\t " + length);
			
			if(override_file_name != null && !override_file_name.trim().equals(""))
				pw.println(header + "file_name" + ":\t " + override_file_name);
			else
				pw.println(header + "file_name" + ":\t " + file_name);
			
			
			pw.println(header + "size" + ":\t " + size);
			pw.println(header + "creation_date" + ":\t " + creation_date);
			pw.println(header + "last_accessed" + ":\t " + last_accessed);
			pw.println(header + "last_modified" + ":\t " + last_modified);
			pw.println(header + "hash_md5" + ":\t " + hash_md5);
			pw.println(header + "hash_sha256" + ":\t " + hash_sha256);
			
			if(is_hashing_complete)
				pw.println(header + "is_hashing_complete" + ":\t " + is_hashing_complete);
			
			if(attributes != null && !attributes.trim().equals("") && !attributes.toLowerCase().trim().equals("not specified"))
				pw.println(header + "attributes" + ":\t " + attributes);
			
			if(short_file_name != null && !short_file_name.trim().equals("") && !short_file_name.toLowerCase().trim().equals("unspecified"))
				pw.println(header + "short_file_name" + ":\t " + short_file_name);
			
			if(is_file)
				pw.println(header + "is_file" + ":\t " + is_file);
			
			if(is_directory)
				pw.println(header + "is_directory" + ":\t " + is_directory);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_entry", e);
		}
		
		return false;
	}
	
	
	public boolean write_manifest_investigation_particulars(PrintWriter pw, String header, String designation, String delimiter)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(header == null)
				header = "";
			
			if(designation == null)
				designation = "";
			
			pw.println(header + delimiter + designation + delimiter + 
					"file_name:" + delimiter + file_name + delimiter + 
					"size:" + delimiter + size + delimiter + 
					"creation:" + delimiter + creation_date + delimiter + 
					"last_access:" + delimiter + last_accessed + delimiter +
					"last_modified:" + delimiter + last_modified + delimiter + 
					"md5:" + delimiter + hash_md5 + delimiter + 
					"sha256:" + delimiter + hash_sha256
					);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_investigation_particulars", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
