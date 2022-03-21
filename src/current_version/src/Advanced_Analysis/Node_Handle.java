/**
 * plugin: handles
 * @author Solomon Sonya
 */
package Advanced_Analysis;

import Advanced_Analysis.*;
import Driver.*;
import Interface.*;
import Plugin.*;
import Worker.*;
import java.awt.event.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.LinkedList;
import java.util.TreeMap;

public class Node_Handle 
{
	public static final String myClassName = "Node_Handle";
	public static volatile Driver driver = new Driver();
	

	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false; 
	
	public volatile String offset = "";
	public volatile int PID = -1;
	public volatile String handle_value = "";
	public volatile String access_value = "";
	public volatile String type = "";
	public volatile String details = "";
	
	public volatile Node_Process process = null;
	
	
	public Node_Handle()
	{
		try
		{
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public String toString()
	{
		try
		{
			return "details: " + details + "\ttype: " + type + "\taccess: " + access_value + "\thandle: " + handle_value + "\tpid: " + PID + "\toffset: " + offset ;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		return ".*..*";
	}
	
	
	public String get_manifest_file_entry(String delimiter)
	{
		try
		{
			delimiter = delimiter + " ";
			
			return "offset: " 	+ delimiter + offset.replace(delimiter, " ") + delimiter + 
					"PID: " 	+ delimiter + PID + delimiter + 
					"handle_value: "	+ delimiter + handle_value.replace(delimiter, " ") + delimiter +
					"access_value: " 	+ delimiter + this.access_value.replace(delimiter, " ") + delimiter +
					"type: " 	+ delimiter + type.replace(delimiter, " ") + delimiter +
					"details: "	+ delimiter + details.replace(delimiter, " ") + delimiter;								
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_manifest_file_entry", e);
		}
		
		return toString();
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
			XREF_SEARCH_HIT_FOUND |= this.check_value(handle_value, "handle_value", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(access_value, "access_value", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(type, "type", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(details, "details", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			
	
			
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
	
	
	public static boolean import_manifest_line_entry(String mtd_designator, String line, Advanced_Analysis_Director director, Node_Process process)
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
			Node_Handle node = new Node_Handle();
			
			//
			//set container structure to node
			//
			if(process != null)
			{
				node.process = process;
				node.PID = process.PID;
			}
			
			//init
			String key = "", value = "";
			String type_lower = "";
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
					if(key.equals("pid"))
					{
						//node.pid = value;						
						
						if(process == null && director != null)
						{
							try	
							{	
								node.PID = Integer.parseInt(value);
								node.process = director.tree_PROCESS.get(node.PID);
							}
							catch(Exception e)
							{
								driver.directive("\nNOTE: I could not set PID in import_manifest_line_entry mtd in " + myClassName + " from key [" + key + "] \t value: [" + value + "] on line --> " + line);
							}
						}
					}
					
					else if(key.equals("offset")) node.offset = value;
					else if(key.equals("handle_value")) node.handle_value = value;
					else if(key.equals("access_value")) node.access_value = value;
					else if(key.equals("type"))	node.type = value;
					else if(key.equals("details"))
					{
						node.details = value;
						process.tree_handles.put(node.details, node);
						
						type_lower = node.type.toLowerCase().trim();

						if(type_lower.startsWith("process"))
							process.tree_handles_Process.put(node.details, node);
						else if(type_lower.startsWith("thread"))
							process.tree_handles_Thread.put(node.details, node);
						else if(type_lower.startsWith("key"))
							process.tree_handles_Key.put(node.details, node);
						else if(type_lower.startsWith("event"))
							process.tree_handles_Event.put(node.details, node);
						else if(type_lower.startsWith("file"))
							process.tree_handles_File.put(node.details, node);
						else if(type_lower.startsWith("directory"))
							process.tree_handles_Directory.put(node.details, node);
						else if(type_lower.startsWith("desktop"))
							process.tree_handles_Desktop.put(node.details, node);
						else if(type_lower.startsWith("port"))
							process.tree_handles_Port.put(node.details, node);
						else if(type_lower.startsWith("keyedevent"))
							process.tree_handles_KeyedEvent.put(node.details, node);
						else if(type_lower.startsWith("symboliclink"))
							process.tree_handles_SymbolicLink.put(node.details, node);
						else if(type_lower.startsWith("section"))
							process.tree_handles_Section.put(node.details, node);
						else if(type_lower.startsWith("windowstation"))
							process.tree_handles_WindowStation.put(node.details, node);
						else if(type_lower.startsWith("mutant"))
							process.tree_handles_Mutant.put(node.details, node);
						else if(type_lower.startsWith("semaphore"))
							process.tree_handles_Semaphore.put(node.details, node);
						else if(type_lower.startsWith("timer"))
							process.tree_handles_Timer.put(node.details, node);
						else if(type_lower.startsWith("waitableport"))
							process.tree_handles_WaitablePort.put(node.details, node);
						else if(type_lower.startsWith("job"))
							process.tree_handles_Job.put(node.details, node);
						else
							process.tree_handles_GENERIC.put(node.details, node);
					}

					
					else
						driver.directive("Unknown import_manifest_line_entry mtd on designation [" + mtd_designator + "] in class: " + myClassName + " at index: [" + i + "] key:[" + key + "] value:[" + value + "] on line --> "  + line);
				}
				catch(Exception e)
				{
					driver.directive("Exception in import_manifest_line_entry mtd on designation [" + mtd_designator + "] in class: " + myClassName + " at index: [" + i + "] key:[" + key + "] value:[" + value + "] on line --> "  + line);
					continue;
				}
			}
			
			/////////////////////////////////////////////////////////////////////////
			// set link key
			/////////////////////////////////////////////////////////////////////////
			//key = node.local_address;

			/////////////////////////////////////////////////////////////////////////
			// link node to containing structure
			/////////////////////////////////////////////////////////////////////////
			//process.tree_netstat.put(key, node);
			
			/////////////////////////////////////////////////////////////////////////
			// link node to director tree
			/////////////////////////////////////////////////////////////////////////
			//if(director != null)
			//	director.tree_NETSTAT.put(process.PID, process); 
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("* * Unknown import_manifest_line_entry key: [" + mtd_designator + "] recieved in " + myClassName);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}


