/**
 * Moddump, modules, modscan, driverscan, drivermodule, driverIRPHook
 * 
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;
import Advanced_Analysis.Analysis_Plugin.*;

public class Node_Driver 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_ModuleDump";
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false;
	
	/**0x0804d7000*/
	public volatile String module_base_module_dump = null;
	
	/**0x823fc398*/
	public volatile String offset_modules = null;
	
	/**0x0000000001cc54f8*/
	public volatile String offset_modscan = null;
	
	/**e.g. ntoskrnl.exe*/
	public volatile String module_name = null;
	
	/**e.g. driver.804d7000.sys*/
	public volatile String dump_file_name = null;
	
	/**From modules e.g. 0x1f8580*/
	public volatile String size_V = null;
	
	/**From modules e.g. \WINDOWS\system32\ntkrnlpa.exe*/
	public volatile String file_path_from_memory = null;
	
	public volatile File fle = null;
	public volatile FileAttributeData fle_attributes = null;
	
	//
	//drivermodule
	//
	public volatile String driver_name = null;
	public volatile String alt_name = null;
	
	//
	//driverscan
	//
	public volatile String offset_driverscan = null;
	public volatile String num_ptr = null;
	public volatile String num_handle = null;
	public volatile String start = null;
	public volatile String service_key = null;
	public volatile String size_P = null;
	
	//
	//driverirp
	//
	public volatile String driver_start_io = null;
	public volatile LinkedList<Node_Driver_IRP>  list_driver_irp = null;
	
	//
	//callbacks
	//
	public volatile TreeMap<String, Node_Generic> tree_callbacks = null;
	
	
	//
	//timers
	//
	public volatile TreeMap<String, Node_Generic> tree_timers = null;
	
	//
	//Unloaded Modules
	//
	public volatile TreeMap<String, Node_Generic> tree_unloaded_modules = null;
	
	
	/**moddump*/
	public Node_Driver(String MODULE_BASE, String Module_Name, String Dump_File_Name)
	{
		try
		{
			module_base_module_dump = MODULE_BASE;
			module_name = Module_Name; 
			dump_file_name = Dump_File_Name; 
			
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
			pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html(this.module_name).replace("\\", "\\\\") + "\" , \"children\": [");
			
			if(this.fle_attributes != null)
				this.fle_attributes.write_node_file_attributes(pw, null, null);
									
			pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html("Details").replace("\\", "\\\\") + "\" , \"children\": [");
				driver.write_node_ENTRY("File Path: ", this.file_path_from_memory, pw);
				driver.write_node_ENTRY("Driver Name: ", this.driver_name, pw);
				driver.write_node_ENTRY("Alt. Name: ", this.alt_name, pw);
				driver.write_node_ENTRY("Service Key: ", this.service_key, pw);
				driver.write_node_ENTRY("Base: ", this.module_base_module_dump, pw);
				driver.write_node_ENTRY("Start: ", this.start, pw);		
				driver.write_node_ENTRY("# Ptr: ", this.num_ptr, pw);
				driver.write_node_ENTRY("# Handle: ", this.num_handle, pw);
				driver.write_node_ENTRY("Size(V): ", this.size_V, pw);
				driver.write_node_ENTRY("Size (P): ", this.size_P, pw);
				driver.write_node_ENTRY("Offset(P) - ModScan: ", this.offset_modscan, pw);
				driver.write_node_ENTRY("Offset(V) - Modules: ", this.offset_modules, pw);
				driver.write_node_ENTRY("Offset(P) - DriverScan: ", this.offset_driverscan, pw);
			pw.println("\t\t" +  "]},");	
			
			//
			//callbacks
			//
			TreeMap<String, Node_Generic> tree = tree_callbacks;
			
			if(tree != null && tree.size() > 0)
			{
				pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html("Callbacks").replace("\\", "\\\\") + "\" , \"children\": [");
									
					for(Node_Generic node : tree.values())
					{
						if(node == null)
							continue;
						
						node.write_node_CALLBACKS(pw, true);												
					}
					
				
				pw.println("\t\t" +  "]},");
			}
			
			//
			//driver irp
			//
			if(this.list_driver_irp != null && this.list_driver_irp.size() > 0)
			{
				pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html("Driver IRP Hook").replace("\\", "\\\\") + "\" , \"children\": [");
									
					int count = 0;			
					for(Node_Driver_IRP driver_irp : this.list_driver_irp)
					{
						if(driver_irp == null)
							continue;
						
						driver_irp.write_node_information(pw);												
					}
					
				
				pw.println("\t\t" +  "]},");
			}
			
			//
			//Timers
			//
			tree = this.tree_timers;
			
			if(tree != null && tree.size() > 0)
			{
				pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html("Timers").replace("\\", "\\\\") + "\" , \"children\": [");
									
					for(Node_Generic node : tree.values())
					{
						if(node == null)
							continue;
						
						node.write_node_Timers(pw, true);												
					}
					
				
				pw.println("\t\t" +  "]},");
			}
			
			//
			//unloaded modules
			//
			tree = this.tree_unloaded_modules;
			
			if(tree != null && tree.size() > 0)
			{
				pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html("Unloaded Modules").replace("\\", "\\\\") + "\" , \"children\": [");
									
					for(Node_Generic node : tree.values())
					{
						if(node == null)
							continue;
						
						node.write_node_UNLOADED_MODULES(pw, true);												
					}
					
				
				pw.println("\t\t" +  "]},");
			}
			
			
			///////////////////////////////////////
			pw.println("\t\t" +  "]},");//end process information			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_information", e);
		}
		
		return false;
	}
	
	
	public boolean write_table_DRIVER_information(PrintWriter pw, boolean include_counts_of_other_trees)
	{
		try
		{
			pw.print("<tr>");
			/////////////////////////////
			
			
			pw.print(" <td> " + driver.normalize_html(this.module_name).replace("\\", "&#92") + "</td>");
			
			
			if(this.fle_attributes != null)
				this.fle_attributes.write_html_table_entries(pw);
			else
			{
				//pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
				this.write_table_cell_entry(pw, "-");
				this.write_table_cell_entry(pw, "-");
				this.write_table_cell_entry(pw, "-");
				this.write_table_cell_entry(pw, "-");
			}
			
			this.write_table_cell_entry(pw, this.file_path_from_memory);
			this.write_table_cell_entry(pw, driver_name);
			this.write_table_cell_entry(pw, alt_name);
			this.write_table_cell_entry(pw, service_key);
			this.write_table_cell_entry(pw, module_base_module_dump);
			this.write_table_cell_entry(pw, start);
			this.write_table_cell_entry(pw, num_ptr);
			this.write_table_cell_entry(pw, num_handle);
			this.write_table_cell_entry(pw, size_V);
			this.write_table_cell_entry(pw, size_P);
			this.write_table_cell_entry(pw, offset_modscan);
			this.write_table_cell_entry(pw, offset_driverscan);
			this.write_table_cell_entry(pw, offset_modules);
			
			if(include_counts_of_other_trees)
			{
			
				if(this.tree_callbacks != null && this.tree_callbacks.size() > 0)
					this.write_table_cell_entry(pw, "" + tree_callbacks.size());
				else
					this.write_table_cell_entry(pw, "0");
				
				if(this.list_driver_irp != null && this.list_driver_irp.size() > 0)
					this.write_table_cell_entry(pw, "" + list_driver_irp.size());
				else
					this.write_table_cell_entry(pw, "0");
				
				if(this.tree_timers != null && this.tree_timers.size() > 0)
					this.write_table_cell_entry(pw, "" + tree_timers.size());
				else
					this.write_table_cell_entry(pw, "0");
				
				if(this.tree_unloaded_modules != null && this.tree_unloaded_modules.size() > 0)
					this.write_table_cell_entry(pw, "" + tree_unloaded_modules.size());
				else
					this.write_table_cell_entry(pw, "0");
			}
			
			
			
			////////////////////		
			pw.print("</tr>");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_DRIVER_information", e);
		}
		
		pw.print("</tr>");
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
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(module_base_module_dump, "module_base_module_dump", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset_modules, "offset_modules", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset_modscan, "offset_modscan", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(module_name, "module_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(dump_file_name, "dump_file_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(size_V, "size_V", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(file_path_from_memory, "file_path_from_memory", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(driver_name, "driver_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(alt_name, "alt_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset_driverscan, "offset_driverscan", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(num_ptr, "num_ptr", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(num_handle, "num_handle", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(start, "start", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(service_key, "service_key", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(size_P, "size_P", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(driver_start_io, "driver_start_io", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);

			//
			//File
			//
			if(fle != null)
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle.getCanonicalPath(), "File", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			

			//
			//File Attributes
			//
			if(this.fle_attributes != null)
			{
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.creation_date, "File Module Creation Date", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.extension, "File Module Extension", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.file_name, "File Module Name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_md5, "File Hash - MD5", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_sha256, "File Hash - Sha256", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_accessed, "File Module Last Accessed", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_modified, "File Module Last Modified", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.size, "File Module Size", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			}
			
			//
			//Callbacks
			//
			if(tree_callbacks != null)
			{
				for(Node_Generic node : tree_callbacks.values())
				{
					if(node == null)
						continue;
					
					node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name + " Callbacks");
				}
			}
			
			//
			//Timers
			//
			if(this.tree_timers != null)
			{
				for(Node_Generic node : tree_timers.values())
				{
					if(node == null)
						continue;
					
					node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name + " Timers");
				}
			}
			
			
			//
			//Unloaded Modules
			//
			if(this.tree_unloaded_modules != null)
			{
				for(Node_Generic node : tree_unloaded_modules.values())
				{
					if(node == null)
						continue;
					
					node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name + " Unloaded Modules");
				}
			}
			
			//
			//Driver IRP
			//
			if(this.list_driver_irp != null)
			{
				for(Node_Driver_IRP node : this.list_driver_irp)
				{
					if(node == null)
						continue;
					
					node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, "Driver IRP");
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
	
	
	
	
	
	
	
}
