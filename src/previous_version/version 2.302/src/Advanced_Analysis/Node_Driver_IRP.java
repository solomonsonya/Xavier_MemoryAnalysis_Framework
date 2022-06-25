/**
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;
import Advanced_Analysis.Analysis_Plugin.*;

public class Node_Driver_IRP 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_Driver_IRP";
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false;
	
	public volatile Node_Driver nde_driver = null;
	public volatile String driver_irp_start = null;
	public volatile String driver_irp_size = null;
	public volatile String driver_irp_start_io = null;
	public volatile LinkedList<String> list_irp_entries = new LinkedList<String>();
	
	public volatile int index = 0;
	
	public Node_Driver_IRP(Node_Driver DRIVER)
	{
		try
		{
			nde_driver = DRIVER;
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
			pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("Hook [" + index + "]").replace("\\", "\\\\") + "\" , \"children\": [");
			
			if(this.nde_driver == null)
				driver.write_node_ENTRY("Driver Name: ", "Driver IRP Hook [" + index + "]", pw);
			else
				driver.write_node_ENTRY("Driver Name: ", this.nde_driver.module_name, pw);
			
			driver.write_node_ENTRY("Driver Start: ", this.driver_irp_start, pw);
			driver.write_node_ENTRY("Driver Size: ", this.driver_irp_size, pw);
			driver.write_node_ENTRY("Driver Start IO: ", this.driver_irp_start_io, pw);
			
			if(this.list_irp_entries != null && this.list_irp_entries.size() > 0)
			{
				pw.println("\t\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("Details").replace("\\", "\\\\") + "\" , \"children\": [");
				
					for(String entry : this.list_irp_entries)
					{
						driver.write_node_ENTRY("", entry, pw);
					}
				
				pw.println("\t\t\t\t" +  "]},");
			}
			
			

			
			
			
			pw.println("\t\t\t" +  "]},");			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_information", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	/**
	 * e.g. given an output like [1512] Winrar.exe Malfind [Detail] - 0x00df0020  fe 07 00 00 48 ff 20 90 41 ba 82 00 00 00 48 b8   ....H...A.....H.
	 * container_search_name == "Malfind", mneumonic == "Detail", search_string could == ff 20 90, output line would be 0x00df0020  fe 07 00 00 48 ff 20 90 41 ba 82 00 00 00 48 b8   ....H...A.....H.
	 * 
	 * @param search_chars_from_user
	 * @param search_chars_from_user_lower
	 * @param jta
	 * @param searching_proces
	 * @param container_search_name
	 * @return
	 */
	public boolean search_XREF(String search_chars_from_user, String search_chars_from_user_lower, JTextArea_Solomon jta, Node_Process searching_proces, String container_search_name)
	{
		try
		{  
			XREF_SEARCH_HIT_FOUND = false;
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(driver_irp_start, "driver_start", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(driver_irp_size, "driver_size", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(driver_irp_start_io, "driver_start_io", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
	
			
			if(this.list_irp_entries != null)
			{
				for(String entry : list_irp_entries)
				{
					XREF_SEARCH_HIT_FOUND |= this.check_value(entry, "Entry", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
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

	/**
	 * e.g. given an output like [1512] Winrar.exe Malfind [Detail] - 0x00df0020  fe 07 00 00 48 ff 20 90 41 ba 82 00 00 00 48 b8   ....H...A.....H.
	 * container_search_name == "Malfind", mneumonic == "Detail", search_string could == ff 20 90, output line would be 0x00df0020  fe 07 00 00 48 ff 20 90 41 ba 82 00 00 00 48 b8   ....H...A.....H.
	 * 
	 * @param value_to_check
	 * @param mneumonic
	 * @param search_string
	 * @param search_string_lower
	 * @param jta
	 * @param searching_proces
	 * @return
	 */
	public boolean check_value(String value_to_check, String mneumonic, String search_string, String search_string_lower, JTextArea_Solomon jta, Node_Process searching_proces, String container_search_name)	
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
				searching_proces.append_to_jta_XREF(container_search_name + " [" + mneumonic + "]: " + value_to_check, jta);
				return true;
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "check_value", e);
		}
		
		return false;
	}
	
		
	public boolean write_manifest(PrintWriter pw, String header)
	{
		try
		{
			driver.write_manifest_entry(pw, header, "driver_irp_start", driver_irp_start);
			driver.write_manifest_entry(pw, header, "driver_irp_size", driver_irp_size);
			driver.write_manifest_entry(pw, header, "driver_irp_start_io", driver_irp_start_io);
			
			if(list_irp_entries != null && !list_irp_entries.isEmpty())
			{
				for(String entry : list_irp_entries)
				{
					driver.write_manifest_entry(pw, header, "list_irp_entries", entry);
				}
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
