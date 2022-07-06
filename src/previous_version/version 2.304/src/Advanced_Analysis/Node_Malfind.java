/**
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;
import Advanced_Analysis.Analysis_Plugin.*;

public class Node_Malfind 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_Malfind";
	
	public volatile Node_Process process = null;
	public volatile String process_name = null;
	public volatile String pid = null;
	public volatile String address = null;
	public volatile String vad_tag = null;
	public volatile String protection = null;
	public volatile String flags = null;
	public volatile boolean MZ_present = false;
	public volatile boolean Trampoline_initial_JMP_Detected = false;
	
	public volatile String culprit_line_MZ = null;
	public volatile String culprit_line_JMP = null;
	
	public volatile File fle = null;
	public volatile FileAttributeData fle_attributes = null;
	/** just to hold descriptor of the file name*/
	public volatile String fle_name_descriptor = null;
	
	public volatile LinkedList<String> list_details = new LinkedList<String>();
	
	public volatile boolean XREF_SEARCH_HIT_FOUND = false;
	
	public volatile String lower = null;
	
	public Node_Malfind(String PROCESS_NAME, String PID, Node_Process PROCESS, String ADDRESS)
	{
		try
		{
			process_name = PROCESS_NAME;
			pid = PID;
			process = PROCESS;
			address = ADDRESS;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
	}
	
	
	
	
	
	
	
	
	
	public boolean write_node_information(PrintWriter pw)
	{
		try
		{
			if(this.MZ_present)
				pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html("[ * MZ Detected * ] " + this.address).replace("\\", "\\\\") + "\" , \"children\": [");
			else if(this.Trampoline_initial_JMP_Detected)
				pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html("[ * JMP Detected * ] " + this.address).replace("\\", "\\\\") + "\" , \"children\": [");
			else
				pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html("" + this.address).replace("\\", "\\\\") + "\" , \"children\": [");

			driver.write_EXPANDED_node_ENTRY("Process Name: ", this.process_name, pw);
			driver.write_EXPANDED_node_ENTRY("PID: ", pid, pw);
			driver.write_EXPANDED_node_ENTRY("Address: ", address, pw);
			driver.write_EXPANDED_node_ENTRY("VAD Tag: " , vad_tag, pw);
			driver.write_EXPANDED_node_ENTRY("Protection: ", protection, pw);
			driver.write_EXPANDED_node_ENTRY("Flags: ", flags, pw);
			driver.write_EXPANDED_node_ENTRY("MZ Detected: ", ""+this.MZ_present, pw);
			driver.write_EXPANDED_node_ENTRY("Trampoline Detected: ", ""+this.Trampoline_initial_JMP_Detected, pw);
			
			//write details
			if(this.list_details != null && this.list_details.size() > 0)
			{
				pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("Details").replace("\\", "\\\\") + "\" , \"children\": [");
				
				for(String entry : this.list_details)
				{										
					if(entry == null)
						continue;
					
					driver.write_node_ENTRY("", entry, pw);
				}
				
				pw.println("\t\t\t" +  "]},");//end process information
			}
			
			pw.println("\t\t" +  "]},");//end process information			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_information", e);
		}
		
		return false;
	}
	
	
	
	public boolean write_dependency_files_MALFIND_table(PrintWriter pw)
	{
		try
		{
			this.write_table_cell_entry(pw, address);
			this.write_table_cell_entry(pw, vad_tag);
			this.write_table_cell_entry(pw, protection);
			this.write_table_cell_entry(pw, flags);
			this.write_table_cell_entry(pw, ""+MZ_present);	
			
						
			if(this.fle_attributes != null)
			{
				if(fle_attributes.fle != null && fle_attributes.fle.isFile() && fle_attributes.fle.exists())
					pw.print(" <td> " + driver.normalize_html(this.fle_attributes.fle.getName()).replace("\\", "&#92") + "</td>");
			
				else if(this.fle_attributes.file_name != null && !this.fle_attributes.file_name.trim().equals(""))
					pw.print(" <td> " + driver.normalize_html(this.fle_attributes.file_name).replace("\\", "&#92") + "</td>");
				
				else
					pw.print(" <td> " + driver.normalize_html("binary_image").replace("\\", "&#92") + "</td>");
				
				this.fle_attributes.write_html_table_entries(pw);
			}
			else
			{
				pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_MALFIND_table", e);
		}
		
		return false;
	}
	
	public boolean write_table_cell_entry(PrintWriter pw, String value)
	{
		try
		{
			pw.print(" <td> " + driver.normalize_html(value).replace("\\", "&#92") + "</td>");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_cell_entry", e);
		}
		
		return false;
	}
	
	
	public boolean store_malfind_file_dump_attributes(File file)
	{
		try
		{
			if(file == null || !file.exists() || !file.isFile())
				return false;
			
			this.fle = file;
			
			this.fle_attributes  = new FileAttributeData(file, process, null);
			this.fle_attributes.set_hash(false);
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "store_malfind_file_dump_attributes", e);
		}
		
		return false;
	}
	
	
	public boolean search_XREF(String search_chars_from_user, String search_chars_from_user_lower, JTextArea_Solomon jta, Node_Process searching_proces)
	{
		try
		{
			XREF_SEARCH_HIT_FOUND = false;
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(address, "Address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);
			XREF_SEARCH_HIT_FOUND |= this.check_value(vad_tag, "VAD Tag", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);
			XREF_SEARCH_HIT_FOUND |= this.check_value(protection, "Memory Protection", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);
			XREF_SEARCH_HIT_FOUND |= this.check_value(flags, "Flags", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);

			//
			//search file
			//
			if(fle != null)
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle.getCanonicalPath(), "File Mem Dump", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);
			
			//
			//search file attributes
			//
			if(this.fle_attributes != null)
			{
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.creation_date, "File Mem Dump Creation Date", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.extension, "File Mem Dump Extension", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.file_name, "File Mem Dump Name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_md5, "File Hash - MD5", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_sha256, "File Hash - Sha256", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_accessed, "File Mem Dump Last Accessed", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_modified, "File Mem Dump Last Modified", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.size, "File Mem Dump Size", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);
			}
			
			//
			//search details
			//
			if(list_details != null)
			{
				for(String detail : list_details)
				{
					XREF_SEARCH_HIT_FOUND |= this.check_value(detail, "Details", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces);
				}
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "search_XREF", e);
		}
		
		lower = null;
		return XREF_SEARCH_HIT_FOUND;
		
	}
	
	
	public boolean check_value(String value_to_check, String mneumonic, String search_string, String search_string_lower, JTextArea_Solomon jta, Node_Process searching_proces)	
	{
		try
		{
			if(value_to_check == null)
				return false;
			
			lower = value_to_check.toLowerCase().trim();
			
			if(lower.equals(""))
				return false;
			
			if(searching_proces == null)
				return false;
			
			if(lower.contains(search_string_lower))
			{
				searching_proces.append_to_jta_XREF("Malfind [" + mneumonic + "]: " + value_to_check, jta);
				return true;
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "check_value", e);
		}
		
		return false;
	}
	
	
	
	/**
	 * continuation mtd
	 * @param pw
	 * @param key
	 * @param value
	 * @return
	 */
	public boolean write_manifest(PrintWriter pw, String header, String delimiter, boolean include_underline)
	{
		try
		{
			if(pw == null)
				return false;	
			
			delimiter = delimiter + " ";
			
			driver.write_manifest_entry(pw, header, 
										"PID: " 			+ delimiter + 	pid 			+ delimiter +
										"process_name: " 	+ delimiter + 	process_name 	+ delimiter +
										"address: " 		+ delimiter + 	address 			+ delimiter +
										"vad_tag: " 		+ delimiter + 	vad_tag 			+ delimiter +
										"protection: " 		+ delimiter + 	protection 			+ delimiter +
										"flags: " 			+ delimiter + 	flags 			+ delimiter +
										"MZ_present: " 		+ delimiter + 	MZ_present 			+ delimiter +
										"Trampoline_initial_JMP_Detected: " 			+ delimiter + 	Trampoline_initial_JMP_Detected);	
			
			if(this.fle != null)
			{
				fle_name_descriptor = "/" + fle.getParentFile().getName() + "/" + fle.getName();
				driver.write_manifest_entry(pw, header, "fle", fle_name_descriptor);				
			}
			else if(fle_name_descriptor != null)
			{
				driver.write_manifest_entry(pw, header, "fle", fle_name_descriptor);
			}
			
			if(this.fle_attributes != null)
				fle_attributes.write_manifest_entry(pw, header + delimiter + "file_attr" + delimiter, null);
			
			if(list_details != null && !list_details.isEmpty())
			{
				for(String entry : list_details)
				{
					driver.write_manifest_entry(pw, header, "list_details:\t " + entry);
				}
			}
			
			if(include_underline)
				pw.println(Driver.END_OF_ENTRY_MINOR);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest", e);
		}
		
		return false;
	}
	
	
	
	
	
	public String get_snapshot_analysis_key()// throws NullPointerException
	{
		try
		{
			return this.address;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_snapshot_analysis_key", e);
		}
		
		return this.address;
	}
	
	
	public String get_snapshot_analysis_COMPARATOR_VALUE()// throws NullPointerException
	{
		String output = "";
		
		try
		{						
			output = output + "pid:\t" +  pid + "\t";
			output = output + "process_name:\t" +  process_name + "\t";
			output = output + "address:\t" +  address + "\t";
			output = output + "vad_tag:\t" +  vad_tag + "\t";
			output = output + "protection:\t" +  protection + "\t";
			output = output + "flags:\t" +  flags + "\t";
			output = output + "MZ_present:\t" +  MZ_present + "\t";
			output = output + "Trampoline_initial_JMP_Detected:\t" +  Trampoline_initial_JMP_Detected + "\t";

		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_snapshot_analysis_COMPARATOR_VALUE", e);
		}
		
		return output;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
