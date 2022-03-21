/**
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;
import Advanced_Analysis.Analysis_Plugin.*;

public class Node_hivelist 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_hivelist";
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false; 
	
	public volatile String virtual_address = null;
	public volatile String physical_address = null;
	public volatile String name_registry = "";
	
	public Node_hivelist()
	{
		try
		{
			
			
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
			
			String header = "";
			
			try	{	header = this.name_registry.substring(name_registry.lastIndexOf("\\")+1).trim();}
			catch(Exception e){	header = this.name_registry;}
			
			pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html(header).replace("\\", "\\\\") + "\" , \"children\": [");

			driver.write_node_ENTRY("Name: ", this.name_registry, pw);
			driver.write_node_ENTRY("Virtual Address: ", this.virtual_address, pw);
			driver.write_node_ENTRY("Physical Address: ", this.physical_address, pw);
			
			pw.println("\t\t\t" +  "]},");//end process information
			
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
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(virtual_address, "virtual_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(physical_address, "physical_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(name_registry, "Registry Name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
	
			
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
	
	
	
	public boolean write_manifest(PrintWriter pw, String header, String delimiter)
	{				
		try
		{
			if(pw == null)
				return false;
			
			if(delimiter == null)
				delimiter = "\t";
			
			delimiter = delimiter + " ";
			
			String output = "virtual_address:\t " + virtual_address + delimiter + 
							"physical_address:\t " + physical_address + delimiter +
							"name_registry:\t " + name_registry;
			
			driver.write_manifest_entry(pw, header, output);
			
						
			
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest", e);
		}
		
		return false;
	}
	
	
	
	/**
	 * import single line entries e.g. 
	 * @param mtd_designator
	 * @param line
	 * @param director
	 * @param process
	 * @param tree_process
	 * @param tree_director
	 * @return
	 */
	public static boolean import_manifest_line_entry_NODE_IS_ENTIRE_LINE(String mtd_designator, String line, Advanced_Analysis_Director director, Node_Process process)
	{
		try
		{
			if(line == null)
				return false;
			
			if(mtd_designator != null && line.toLowerCase().trim().startsWith(mtd_designator.toLowerCase().trim()))
				line = driver.trim_key(mtd_designator, line, true);					
			
			String arr [] = line.split("\t");
			
			//validate entries
			if(arr == null || arr.length < 2)
			{
				driver.directive("* * * invalid import_manifest_line_entry mtd_designator: [" + mtd_designator + "] recieved in " + myClassName + "\t line --> " + line);
				return false;
			}
			
			//validate key, value tuple(s)
			if(arr.length%2 != 0)
			{
				driver.directive("* * * incongruent import_manifest_line_entry mtd_designator: [" + mtd_designator + "] recieved in " + myClassName + "\t line --> " + line);
				return false;
			}
			
			/////////////////////////////////////////////////////////////////////////
			// instantiate node
			/////////////////////////////////////////////////////////////////////////
			Node_hivelist node = new Node_hivelist();
			
			
			//
			//set container structure to node
			//
			if(process == null)
				process = director.NULL_PROCESS;
			
			//node.process = process;
			//node.PID = process.PID;

			//remove if superfluous
			//node.pid = "" + process.PID;				
			
			
			//init
			String key = "", value = "";
			
			//
			//process entry
			//
			for(int i = 0; i < arr.length; i+=2)
			{
				try
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					if(key.endsWith(":"))
						key = key.substring(0, key.length()-1).trim();

				
					
					/////////////////////////////////////////////////////////////////////////
					// set values
					/////////////////////////////////////////////////////////////////////////
					if(key.equals("virtual_address")) node.virtual_address = value;
					else if(key.equals("physical_address")) node.physical_address = value;
					else if(key.equals("name_registry")) node.name_registry = value;

					
					
					else
						driver.directive("Unknown import_manifest_line_entry in class: " + myClassName + " at index: [" + i + "] key:[" + key + "] value:[" + value + "] on line --> "  + line);
				}
				catch(Exception e)
				{
					driver.directive("Exception in import_manifest_line_entry in class: " + myClassName + " at index: [" + i + "] key:[" + key + "] value:[" + value + "] on line --> "  + line);
					continue;
				}
			}
			
			/////////////////////////////////////////////////////////////////////////
			// Store values!
			/////////////////////////////////////////////////////////////////////////
			director.tree_hivelist.put(node.name_registry, node);
			
			
		}
		catch(Exception e)
		{
			driver.directive("* * Unknown import_manifest_line_entry key: [" + mtd_designator + "] recieved in " + myClassName + "\t line --> " + line);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
}
