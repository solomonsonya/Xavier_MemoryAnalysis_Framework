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
	
	public volatile String registry_hive = null;
	
	public volatile TreeMap<String, Node_Registry_Key> tree_registry_key = new TreeMap<String, Node_Registry_Key>();
	
	public volatile String last_updated = null;
	public volatile String path = null;
	
	public volatile Node_Registry_Key registry_key = null; 
	public volatile Node_Generic registry_subkey = null;
	
	public volatile Advanced_Analysis_Director director = null;
	
	
	public Node_Registry_Hive() 
	{
		try
		{
			
		}
		catch(Exception e)
		{
			
		}
		
	}
	
	/**Registry: \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT*/
	public Node_Registry_Hive(String REGISTRY)
	{
		try
		{
			registry_hive = REGISTRY;
			
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
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(this.registry_hive, "registry", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
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
					if(node.tree_reg_subkey != null)
					{
						for(Node_Generic nde : node.tree_reg_subkey.values())
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
				jta.append("\n\nRegistry Hive: " + this.registry_hive + "\n" + driver.UNDERLINE);
			
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
	
	
	
	public boolean write_manifest(PrintWriter pw, String header, String delimiter, Advanced_Analysis_Director director)
	{				
		try
		{
			if(pw == null)
				return false;
			
			if(delimiter == null)
				delimiter = "\t ";
			
			driver.write_manifest_entry(pw, header, "registry_hive", registry_hive);
			driver.write_manifest_entry(pw, header, "path", path);
			driver.write_manifest_entry(pw, header, "last_updated", last_updated);
			
			if(this.tree_registry_key == null || this.tree_registry_key.isEmpty())
				return true;
			
			for(Node_Registry_Key registry_key : this.tree_registry_key.values())
			{								
				if(registry_key == null)
					continue;
				
				registry_key.write_manifest(pw, header, delimiter, director);
			
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
	
	
	
	
	public boolean import_manifest_line_entry(String line_entry, String []arr, String key, String value, Advanced_Analysis_Director DIRECTOR, TreeMap<String, Node_Registry_Hive> tree)
	{
		try
		{
			if(key == null || value == null)
				return false;
			
			key = key.trim();
			value = value.trim();
			
			if(key.endsWith(":"))
				key = key.substring(0, key.length()-1);
			
			if(value.endsWith(":"))
				value = value.substring(0, value.length()-1);
			
			director = DIRECTOR;
								
			String line_entry_lower = line_entry.toLowerCase().trim();
			String value_lower = "";
			
			//
			//Particulars
			//
			if(key.equals("registry_hive"))  
			{
				//should already be linked by the caller function, if not, ensure to link to supplied tree!
				registry_hive = value;
			}
			else if(key.equals("last_updated"))  
			{
				last_updated = value;
			}
			
			else if(key.equals("path"))  
			{
				path = value;
			}
			////////////////////////////////////////////////////////////////////////////////////////////////
			//
			// registry_key
			//
			///////////////////////////////////////////////////////////////////////////////////////////////
			else if(key.equals("registry_key"))
			{
				line_entry = driver.trim_key(key, line_entry, true);
				
				arr = line_entry.split("\t");
				key = arr[0].toLowerCase().trim();
				value = arr[1];		
				value_lower = value.toLowerCase().trim();
				

				if(key.equals("parent_container_registry"))
				{
					value = driver.trim_key(key, line_entry, true);
					value_lower = value.toLowerCase().trim();		
					
					//do n/t, parent contianer for key is already set by self (by default)
				}
				
				//
				//create new key. this is for PRINT_KEY
				//
				else if(key.equals("key_name"))
				{
					value = driver.trim_key(key, line_entry, true);
					value_lower = value.toLowerCase().trim();
					
					registry_key = this.tree_registry_key.get(value_lower);

					if(registry_key == null)
					{
						registry_key = new Node_Registry_Key(this, null);						
						this.tree_registry_key.put(value_lower, registry_key);
						registry_key.key_name = value;
					}

					if(registry_key != null)
						registry_key.key_name = value;
				}
				
				//
				// last updated
				//
				else if(key.equals("last_updated"))
				{
					value = driver.trim_key(key, line_entry, true);

					if(registry_key != null)				registry_key.last_updated = value;
				}
				
				//
				//list_sub_key_names - used in PRINT_KEY
				//
				else if(key.equals("list_sub_key_names"))
				{
					value = driver.trim_key(key, line_entry, true);

					if(registry_key != null)
					{
						if(registry_key.list_sub_key_names == null)
							registry_key.list_sub_key_names = new LinkedList<String>();
						
						if(!registry_key.list_sub_key_names.contains(value))
							registry_key.list_sub_key_names.add(value);
					}
				}
				
				//
				//list_values - this is used in PRINT_KEY
				//
				else if(key.equals("list_values"))
				{
					value = driver.trim_key(key, line_entry, true);

					if(registry_key != null)
					{
						if(registry_key.list_values == null)
							registry_key.list_values = new LinkedList<String>();

						if(!registry_key.list_values.contains(value))
							registry_key.list_values.add(value);
					}
				}
				
				//
				//PATH - CREATE NEW NODE!  this is used by USER_ASSIST 
				//
				else if(key.equals("path") && tree == director.tree_REGISTRY_HIVE_USER_ASSIST)
				{
					value = driver.trim_key(key, line_entry, true);					
					String path = value;
					String path_lower = value.toLowerCase().trim();
								
					registry_key = this.tree_registry_key.get(path_lower);
															
					if(registry_key == null)
					{
						registry_key = new Node_Registry_Key(this, path);
						this.tree_registry_key.put(path_lower, registry_key);
					}	
					
					//added this part later... - Solo
					if(this.path == null || this.path.length() < 1)
						this.path = path;										
				}

			}

			////////////////////////////////////////////////////////////////////////////////////////////////
			//
			// registry_subkey
			//
			///////////////////////////////////////////////////////////////////////////////////////////////
			else if(key.equals("registry_subkey"))  // - used by USER_ASSIST
			{
				line_entry = driver.trim_key(key, line_entry, true);

				arr = line_entry.split("\t");
				key = arr[0].toLowerCase().trim();
				value = arr[1];		
				value_lower = value.toLowerCase().trim();

				//
				//parent_container_registry
				//
				if(key.equals("parent_container_registry"))
				{
					value = driver.trim_key(key, line_entry, true);
					value_lower = value.toLowerCase().trim();		

					//do n/t, parent contianer for key is already set by self (by default)
				}

				// * * * CREATE NEW NODE --> registry_subkey
				//plugin_name - used by USER_ASSIST
				//
				else if(key.equals("plugin_name"))
				{
					value = driver.trim_key(key, line_entry, true);
					value_lower = value.toLowerCase().trim();
					
					this.registry_subkey = new Node_Generic(value);																				
				}
				
				//* * * CREATE NEW SUB KEY NODE!
				//
				//reg_binary
				//
				else if(key.equals("reg_binary")) //used by USER_ASSIST
				{
					value = driver.trim_key(key, line_entry, true);
					value_lower = value.toLowerCase().trim();

					if(registry_key == null && this.path != null && this.path.trim().length() > 1)
					{
						registry_key = new Node_Registry_Key(this, path);
						this.tree_registry_key.put(path.toLowerCase().trim(), registry_key);						
					}
									
					//
					// create new subkey node!
					//
					if(registry_key != null)
					{
						if(registry_key.tree_reg_subkey == null)
							registry_key.tree_reg_subkey = new TreeMap<String, Node_Generic>();
						
						registry_subkey = registry_key.tree_reg_subkey.get(value_lower);
						
						if(registry_subkey == null)
						{
							this.registry_subkey = new Node_Generic("user_assist");
							registry_subkey.reg_binary = value;
							registry_subkey.registry_key = registry_key;
							registry_subkey.registry_hive = this;
							
							//link
							registry_key.tree_reg_subkey.put(value_lower, registry_subkey);
						}
					}
					else
						driver.directive("Error importing reb_binary in " + myClassName + " - registry_key is null!");									
				}
				
				//
				//raw_data_first_line
				//
				else if(key.equals("raw_data_first_line"))
				{
					value = driver.trim_key(key, line_entry, true);
					value_lower = value.toLowerCase().trim();		
					
					if(registry_subkey != null)
					{
						registry_subkey.raw_data_first_line = value;
					}					
				}

				//
				//count
				//
				else if(key.equals("count"))
				{
					value = driver.trim_key(key, line_entry, true);
					value_lower = value.toLowerCase().trim();		
					
					if(registry_subkey != null)
					{
						registry_subkey.count = value;
					}					
				}
				
				//
				//focus_count
				//
				else if(key.equals("focus_count"))
				{
					value = driver.trim_key(key, line_entry, true);
					value_lower = value.toLowerCase().trim();		
					
					if(registry_subkey != null)
					{
						registry_subkey.focus_count = value;
					}					
				}
				
				//
				//time_focused
				//
				else if(key.equals("time_focused")) // see analyze_user_agent mtd in Analysis_Plugin_user_assist to see how to update GUI with these entries!
				{
					value = driver.trim_key(key, line_entry, true);
					value_lower = value.toLowerCase().trim();		
					
					if(registry_subkey != null)
					{
						registry_subkey.time_focused = value;
						
						//store this key by the time it has been focused
						if(registry_subkey.time_focused != null && registry_subkey.time_focused.trim().length() > 0)
						{
							try
							{
								LinkedList<Node_Generic> list = director.tree_user_assist_linked_by_time_focused.get(registry_subkey.time_focused);
								
								//create new list if necessary
								if(list == null)
								{
									list = new LinkedList<Node_Generic>();
									director.tree_user_assist_linked_by_time_focused.put(registry_subkey.time_focused, list);
								}
								
								//link!
								list.add(registry_subkey);
								 
							}
							catch(Exception e)
							{
								driver.sop("In " + this.myClassName + " I had trouble locating linked list for focussed time [" + registry_subkey.time_focused + "]");
							}
						}												
					}	
					
					
				}
				
				//
				//last_updated
				//
				else if(key.equals("last_updated"))
				{
					value = driver.trim_key(key, line_entry, true);
					value_lower = value.toLowerCase().trim();		
					
					if(registry_subkey != null)
					{
						registry_subkey.last_updated = value;
					}					
				}
				
				//
				//id
				//
				else if(key.equals("id"))
				{
					value = driver.trim_key(key, line_entry, true);
					value_lower = value.toLowerCase().trim();		
					
					if(registry_subkey != null)
					{
						registry_subkey.id = value;
					}					
				}
				
				//
				//list_values
				//
				else if(key.equals("list_details"))
				{
					value = driver.trim_key(key, line_entry, true);

					if(registry_subkey != null)
					{
						if(registry_subkey.list_details == null)
							registry_subkey.list_details = new LinkedList<String>();

						if(!registry_subkey.list_details.contains(value))
							registry_subkey.list_details.add(value);											
					}
				}
								
				
//				//
//				//template
//				//
//				else if(key.equals("template"))
//				{
//					value = driver.trim_key(key, line_entry, true);
//					value_lower = value.toLowerCase().trim();		
//					
//					if(registry_subkey != null)
//					{
//						registry_subkey.template = value;
//					}					
//				}
				
				
//				//
//				//last_updated
//				//
//				else if(key.equals("last_updated"))
//				{
//					value = driver.trim_key(key, line_entry, true);
//
//					if(registry_subkey != null)				
//						registry_subkey.last_updated = value;
//				}
//				
//				//
//				//list_sub_key_names
//				//
//				else if(key.equals("list_sub_key_names"))
//				{
//					value = driver.trim_key(key, line_entry, true);
//
//					if(registry_subkey != null)
//					{
//						if(registry_key.list_sub_key_names == null)
//							registry_key.list_sub_key_names = new LinkedList<String>();
//
//						if(!registry_key.list_sub_key_names.contains(value))
//							registry_key.list_sub_key_names.add(value);
//					}
//				}
//
//				//
//				//list_values
//				//
//				else if(key.equals("list_values"))
//				{
//					value = driver.trim_key(key, line_entry, true);
//
//					if(registry_key != null)
//					{
//						if(registry_key.list_values == null)
//							registry_key.list_values = new LinkedList<String>();
//
//						if(!registry_key.list_values.contains(value))
//							registry_key.list_values.add(value);
//					}
//				}
//				
				
				
				else
					driver.directive("UNKNOWN registry_subkey directive received in " + this.myClassName  + " --> " + line_entry);

			}
			
			

			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			//
			//fle_attributes
			//
//			else if(key.startsWith("file_attr"))  
//			{
//				if(this.fle_attributes == null)
//					this.fle_attributes = new FileAttributeData(this);
//												
//				fle_attributes.import_manifest_entry(key, value, line_entry);
//			}
			
			
			
			
			
			
			
			
			
			
			
			
			
			else
				driver.directive("Unknown import_manifest_line_entry key: [" + key + "] recieved in " + this.myClassName);
			
			return true;
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "import_manifest_line_entry", e);
			driver.directive("* * Unknown import_manifest_line_entry key: [" + key + "] recieved in " + this.myClassName);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
