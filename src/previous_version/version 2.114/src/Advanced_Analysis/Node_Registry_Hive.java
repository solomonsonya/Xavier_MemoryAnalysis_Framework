/**
 * @author Solomon Sonya
 * 
 * e.g. 
 * PrintKey and Userassist plugins - \??\C:\Documents and Settings\Adham\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;
import Advanced_Analysis.Analysis_Plugin.*;

public class Node_Registry_Hive 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_Registry_Hive";
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false;  
	public volatile boolean I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = false;  
	
	public volatile String registry = null;
	
	public volatile TreeMap<String, Node_Registry_Key> tree_registry_key = new TreeMap<String, Node_Registry_Key>();
	
	public volatile String last_updated = null;
	public volatile String path = null;
	
	/**Registry: \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT*/
	public Node_Registry_Hive(String REGISTRY)
	{
		try
		{
			registry = REGISTRY;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
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
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(this.registry, "registry", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(this.last_updated, "last_updated", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(this.path, "path", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			
			if(this.tree_registry_key != null)
			{
				for(Node_Registry_Key node : this.tree_registry_key.values())
				{
					if(node == null)
						continue;
					
					//
					//search Node_Registry_Key
					//
					XREF_SEARCH_HIT_FOUND |= this.check_value(node.key_name, "key_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
					XREF_SEARCH_HIT_FOUND |= this.check_value(node.path, "path", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
					XREF_SEARCH_HIT_FOUND |= this.check_value(node.last_updated, "last_updated", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
					
					if(node.list_sub_key_names != null)
					{
						for(String element : node.list_sub_key_names)
							XREF_SEARCH_HIT_FOUND |= this.check_value(element, "Sub Key", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
					}
					
					if(node.list_values != null)
					{
						for(String element : node.list_values)
							XREF_SEARCH_HIT_FOUND |= this.check_value(element, "Sub Value", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
					}
					
					//
					//tree node generic, userassist
					//
					if(node.tree_reg_binary != null)
					{
						for(Node_Generic nde : node.tree_reg_binary.values())
						{
							if(nde == null)
								continue;
							
							//
							//search ussesrassist
							//
							XREF_SEARCH_HIT_FOUND |= this.check_value(nde.reg_binary, "reg_binary", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
							XREF_SEARCH_HIT_FOUND |= this.check_value(nde.raw_data_first_line, "raw_data_first_line", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
							XREF_SEARCH_HIT_FOUND |= this.check_value(nde.id, "id", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
							XREF_SEARCH_HIT_FOUND |= this.check_value(nde.count, "count", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
							XREF_SEARCH_HIT_FOUND |= this.check_value(nde.focus_count, "focus_count", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
							XREF_SEARCH_HIT_FOUND |= this.check_value(nde.time_focused, "time_focused", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
							XREF_SEARCH_HIT_FOUND |= this.check_value(nde.last_updated, "last_updated", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
					
						}
					}
					
					
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
						
			
			if(lower.contains(search_string_lower))
			{
				if(searching_proces != null)
					searching_proces.append_to_jta_XREF(container_search_name + " [" + mneumonic + "]: " + value_to_check, jta);
				else
					append_to_jta_XREF(container_search_name + " [" + mneumonic + "]: " + value_to_check, jta);
				
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
				jta.append("\n\nRegistry Hive: " + this.registry + "\n" + driver.UNDERLINE);
			
			I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = true;
			
			/*if(this.parent_process != null)
				jta.append("Parent Process: " + this.parent_process.get_process_html_header());
			else if(this.PPID > -1)
				jta.append("PPID: " + this.parent_process.get_process_html_header());*/									
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
	
	
	
	public boolean write_manifest(PrintWriter pw, String header, String delimiter)
	{				
		try
		{
			if(pw == null)
				return false;
			
			if(delimiter == null)
				delimiter = "\t ";
			
			driver.write_manifest_entry(pw, header, "registry_hive", registry);
			driver.write_manifest_entry(pw, header, "path", path);
			driver.write_manifest_entry(pw, header, "last_updated", last_updated);
			
			if(this.tree_registry_key == null || this.tree_registry_key.isEmpty())
				return true;
			
			for(Node_Registry_Key registry_key : this.tree_registry_key.values())
			{								
				if(registry_key == null)
					continue;
				
				registry_key.write_manifest(pw, header, delimiter);
			
				if(registry_key.path != null)
					pw.println(Driver.END_OF_ENTRY_MINOR);
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
