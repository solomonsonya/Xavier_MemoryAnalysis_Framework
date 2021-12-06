/**
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;
import Advanced_Analysis.Analysis_Plugin.*;

public class Node_Registry_Key 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_Registry_Key";
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false; 
	
	public volatile Node_Registry_Hive registry_hive = null;
	
	/**Path: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{75048700-EF1F-11D0-9888-006097DEACF9}\Count*/
	public volatile String path = null;
	
	public volatile TreeMap<String, Node_Generic> tree_reg_binary = new TreeMap<String, Node_Generic>();
	
	public volatile String last_updated = null;
	
	/**set by print_key plugin*/
	public volatile LinkedList<String> list_sub_key_names = null;
	
	public volatile LinkedList<String> list_values = null; 
	
	/**set by print_key plugin*/
	public volatile String key_name = null;
	
	/**
	 * HIVE: Registry: \Device\HarddiskVolume1\Documents and Settings\Adham\NTUSER.DAT  -- PATH: Path: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{75048700-EF1F-11D0-9888-006097DEACF9}\Count*/
	public Node_Registry_Key(Node_Registry_Hive Registry_Hive, String PATH)
	{
		try
		{
			registry_hive = Registry_Hive;
			path = PATH;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
	}
	
	
	
	public boolean write_node_information_USER_ASSIST(PrintWriter pw)
	{
		try
		{
			String entry = path;
			
			//entry = driver.get_value_from_second_to_last_token("\\", path);
			
			//if(entry == null || entry.trim().length() < 2 || !entry.contains("\\"))
			//	entry = path;
			
			if(entry.contains("\\"))
				entry = entry.substring(entry.lastIndexOf("\\")+1).trim();
			
			pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html(entry).replace("\\", "\\\\") + "\" , \"children\": [");

				driver.write_EXPANDED_node_ENTRY("Path", this.path, pw);
				driver.write_EXPANDED_node_ENTRY("Last Updated", this.last_updated, pw);
			
				if(this.tree_reg_binary != null && this.tree_reg_binary.size() > 0)
				{
					for(Node_Generic node : this.tree_reg_binary.values())
					{
						if(node == null)
							continue;
						
						node.write_node_User_Assist(node.reg_binary, pw);
					}
				}
			
			
			pw.println("\t\t" +  "]},");//end process information			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_information_USER_ASSIST", e);
		}
		
		return false;
	}
	
	public boolean write_node_information_PRINT_KEY(PrintWriter pw)
	{
		try
		{						
			pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html(this.key_name).replace("\\", "\\\\") + "\" , \"children\": [");

				driver.write_EXPANDED_node_ENTRY("Key Name", this.key_name, pw);
				driver.write_EXPANDED_node_ENTRY("Last Updated", this.last_updated, pw);
			
				if(this.list_sub_key_names != null && this.list_sub_key_names.size() > 0)
				{
					driver.write_node_LIST_ENTRIES("SubKeys", list_sub_key_names, pw);
					
					/*pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("Subkeys").replace("\\", "\\\\") + "\" , \"children\": [");		
					
					for(String entry : this.list_sub_key_names)
					{
						if(entry == null)
							continue;
						
						driver.write_node_ENTRY("", entry, pw);
					}
					
					pw.println("\t\t" +  "]},");//end process information*/
				}
				
				if(this.list_values != null && this.list_values.size() > 0)
				{
					driver.write_node_LIST_ENTRIES("Values", list_sub_key_names, pw);
					
					/*pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("Values").replace("\\", "\\\\") + "\" , \"children\": [");		
					
					for(String entry : this.list_values)
					{
						if(entry == null)
							continue;
						
						driver.write_node_ENTRY("", entry, pw);
					}
					
					pw.println("\t\t" +  "]},");//end process information*/
				}
			
			
			pw.println("\t\t" +  "]},");//end process information			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_information_PRINT_KEY", e);
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
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(key_name, "key_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(path, "path", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(last_updated, "last_updated", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			
			if(list_sub_key_names != null)
			{
				for(String element : list_sub_key_names)
					XREF_SEARCH_HIT_FOUND |= this.check_value(element, "Sub Key", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			}
			
			if(list_values != null)
			{
				for(String element : list_values)
					XREF_SEARCH_HIT_FOUND |= this.check_value(element, "Sub Value", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			}
			
			if(tree_reg_binary != null)
			{
				for(Node_Generic node : tree_reg_binary.values())
				{
					if(node == null)
						continue;
					
					node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, "Registry Binary");
				}
			}
			
			if(registry_hive != null)
				registry_hive.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			
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
	
	
	
	
	
	
	
	
	
}