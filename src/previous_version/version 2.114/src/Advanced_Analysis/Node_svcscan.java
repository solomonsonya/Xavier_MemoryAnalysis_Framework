/**
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;
import Advanced_Analysis.Analysis_Plugin.*;
import Advanced_Analysis.Analysis_Report.Dependency_File_Writer_Tree;

public class Node_svcscan 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_svcscan";
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false;  
	public volatile boolean I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = false;  
	
	public volatile String offset = null;
	public volatile String order = null;
	public volatile String start = null;
	public volatile String pid = null;
	public volatile int PID = -1;
	public volatile String service_name = null;
	public volatile String display_name = null;
	public volatile String service_type = null;
	public volatile String service_state = null;
	public volatile String binary_path = null;
	
	public volatile Node_Process process = null;
	
	public Node_svcscan(String SERVICE_NAME)
	{
		try
		{
			service_name = SERVICE_NAME;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
	}
	
	
	
	
	public boolean write_tree_information(PrintWriter pw, Dependency_File_Writer_Tree dependency_writer)
	{
		try
		{
			//name node
			pw.println("\t" +  "{ \"name\": \"" + driver.normalize_html(this.service_name).replace("\\", "\\\\") + "\" , \"children\": [");
			
			driver.write_node_ENTRY("Offset: ", offset, pw);
			driver.write_node_ENTRY("Start: ", start, pw);
			driver.write_node_ENTRY("PID: ", pid, pw);
			driver.write_node_ENTRY("Service Name: ", service_name, pw);
			driver.write_node_ENTRY("Display Name: ", display_name, pw);
			driver.write_node_ENTRY("Service Type: ", service_type, pw);
			driver.write_node_ENTRY("Service State: ", service_state, pw);
			driver.write_node_ENTRY("Binary Path: ", binary_path, pw);
			
			
			pw.println("\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_tree_information", e);
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
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset, "offset", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(order, "order", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(start, "start", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(pid, "pid", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(service_name, "service_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(display_name, "display_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(service_type, "service_type", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(service_state, "service_state", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(binary_path, "binary_path", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);

	
			
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
			
			//if(searching_proces == null)
			//	return false;
			
			if(lower.contains(search_string_lower))
			{
				if(searching_proces != null)
					searching_proces.append_to_jta_XREF(container_search_name + " [" + mneumonic + "]: " + value_to_check, jta);
				else
					this.append_to_jta_XREF(container_search_name + " [" + mneumonic + "]: " + value_to_check, jta);
				
				return true;
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "check_value", e);
		}
		
		return false;
	}
	
	
	
	
	/**Write PROCESS header and underline about this process when a hit is found, however only do this once per XREF search.  This function is to 
	 * simplify the code such that I don't have to check this value each time*/
	public boolean write_process_header_for_XREF_hit(JTextArea_Solomon jta)
	{
		try
		{
			if(I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY)
				return true;					
			
			//hit found!
			if(jta != null)
				jta.append("\n\nService: " + this.display_name + "[" + this.service_name + "]" + "\n" + driver.UNDERLINE);
			
			I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = true;
										
		}
		catch(Exception e)
		{
			driver.eop(this.myClassName, "write_header_for_XREF_hit",  e);
		}
		
		return false;
	}
	
	public boolean append_to_jta_XREF(String out, JTextArea_Solomon jta)
	{
		try
		{
			XREF_SEARCH_HIT_FOUND = true;
			
			if(jta == null)
				return false;
			
			write_process_header_for_XREF_hit(jta);
			
			jta.append(out);			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "append_to_jta_XREF", e);
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
	public boolean write_manifest(PrintWriter pw, String header, String delimiter)
	{
		try
		{
			if(pw == null)
				return false;	
			
			delimiter = delimiter + " ";
			
			return driver.write_manifest_entry(pw, header, 
										"PID: " 			+ delimiter +	PID 			+ delimiter +
										"offset: " 			+ delimiter + 	offset			+ delimiter +
										"order: " 			+ delimiter + 	order			+ delimiter +
										"start: " 			+ delimiter + 	start			+ delimiter +
										"pid: " 			+ delimiter + 	pid			 	+ delimiter +
										"service_name: " 	+ delimiter + 	service_name 	+ delimiter +
										"display_name: " 	+ delimiter + 	display_name 	+ delimiter +
										"service_type: " 	+ delimiter + 	service_type 	+ delimiter +
										"service_state: " 	+ delimiter + 	service_state 	+ delimiter +
										"binary_path: " 	+ delimiter + 	binary_path);						
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
