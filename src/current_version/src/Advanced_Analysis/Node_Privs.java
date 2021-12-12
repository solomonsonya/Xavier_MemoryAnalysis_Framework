/**
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import java.io.*;
import java.util.*;
import Driver.*;
import Interface.JTextArea_Solomon;

public class Node_Privs 
{
	public static final String myClassName = "Node_Privs";
	public static volatile Driver driver = new Driver();
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false;
	
	Node_Process process = null;
	public volatile int PID = -1;
	public volatile String process_name = "";
	public volatile String value = null;
	public volatile String privilege = null;
	public volatile String privilege_lower = null;
	public volatile String attributes = null;
	public volatile String description = "";
	
	
	
	
	
	
	
	public Node_Privs(Node_Process PROCESS, int pid, String PROCESS_NAME, String VALUE, String PRIVELEGE, String ATTRIBUTES, String DESCRIPTION)
	{
		try
		{
			process = PROCESS;
			PID = pid;
			privilege = PRIVELEGE;
			process_name = PROCESS_NAME;
			attributes = ATTRIBUTES;
			description = DESCRIPTION;
			value = VALUE;
			
			privilege = privilege.trim();
			privilege_lower = privilege.toLowerCase().trim();
			
			//link
			if(process != null && privilege != null && !privilege.equals(""))
			{
				if(process.tree_privs == null)
					process.tree_privs = new TreeMap<String, Node_Privs>();
					
				process.tree_privs.put(privilege_lower,  this);								
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	public boolean write_tree_entry(PrintWriter pw)
	{
		try
		{
			this.write_node_ENTRY("PID: ", ""+this.PID, pw);
			this.write_node_ENTRY("Process Name: ", this.process_name, pw);
			this.write_node_ENTRY("Value: ", this.value, pw);
			this.write_node_ENTRY("Privilege: ", this.privilege, pw);
			this.write_node_ENTRY("Attributes: ", this.attributes, pw);
			this.write_node_ENTRY("Description: ", this.description, pw);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_tree_entry", e);
		}
		
		return false;
	}
	
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
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(value, "value", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(privilege, "privilege identifier", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(attributes, "attributes", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(description, "description", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
	
			
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
										"PID: " 			+ delimiter + 	PID 			+ delimiter +
										"process_name: " 	+ delimiter + 	process_name 	+ delimiter +
										"value: " 			+ delimiter + 	value 			+ delimiter +
										"privilege: " 		+ delimiter + 	privilege 			+ delimiter +
										"privilege_lower: " + delimiter + 	privilege_lower 			+ delimiter +
										"attributes: " 		+ delimiter + 	attributes 			+ delimiter +
										"description: " 	+ delimiter + 	description);						
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
