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
	public static final String myClassName = "Node_svcscan";
	
	public volatile Node_Process process = null;
	public volatile String process_name = null;
	public volatile String pid = null;
	public volatile String address = null;
	public volatile String vad_tag = null;
	public volatile String protection = null;
	public volatile String flags = null;
	public volatile boolean MZ_present = false;
	public volatile boolean Trampoline_initial_JMP_Detected = false;
	
	public volatile File fle = null;
	public volatile FileAttributeData fle_attributes = null;
	
	public volatile LinkedList<String> list_details = new LinkedList<String>();
	
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
				pw.print(" <td> " + driver.normalize_html(this.fle_attributes.fle.getName()).replace("\\", "&#92") + "</td>");
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
	
	
	
	
	
	
}
