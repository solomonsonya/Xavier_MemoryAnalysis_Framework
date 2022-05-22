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
	public static final String myClassName = "Node_Driver";
	
	/**pupulated during import_manifest fcn*/
	public volatile Advanced_Analysis_Director director = null;
	
	public volatile boolean I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = false;
	
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
	public volatile String start_io = null;
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
	
	//
	//import manifest
	//
	Node_Driver_IRP node_driver_irp_import_manifest = null;
	
	/**populated during import_manifest*/
	public volatile String module_name_without_extension = null;
				
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
	public boolean search_XREF(String search_chars_from_user, String search_chars_from_user_lower, JTextArea_Solomon jta, Node_Process searching_proces, Node_Driver searching_module, String container_search_name)
	{
		try
		{  
			XREF_SEARCH_HIT_FOUND = false;
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(module_base_module_dump, "module_base_module_dump", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset_modules, "offset_modules", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset_modscan, "offset_modscan", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(module_name, "module_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(dump_file_name, "dump_file_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(size_V, "size_V", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(file_path_from_memory, "file_path_from_memory", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(driver_name, "driver_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(alt_name, "alt_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset_driverscan, "offset_driverscan", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(num_ptr, "num_ptr", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(num_handle, "num_handle", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(start, "start", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(service_key, "service_key", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(size_P, "size_P", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(start_io, "driver_start_io", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);

			//
			//File
			//
			if(fle != null)
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle.getCanonicalPath(), "File", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
			

			//
			//File Attributes
			//
			if(this.fle_attributes != null)
			{
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.creation_date, "File Module Creation Date", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.extension, "File Module Extension", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.file_name, "File Module Name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_md5, "File Hash - MD5", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_sha256, "File Hash - Sha256", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_accessed, "File Module Last Accessed", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_modified, "File Module Last Modified", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.size, "File Module Size", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_module, container_search_name);
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
	public boolean check_value(String value_to_check, String mneumonic, String search_string, String search_string_lower, JTextArea_Solomon jta, Node_Process searching_proces, Node_Driver searching_module, String container_search_name)	
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
				if(searching_module != null)
					searching_module.append_to_jta_XREF(container_search_name + " [" + mneumonic + "]: " + value_to_check, jta);
				
				else if(searching_proces != null)
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
	
	public String get_module_name()
	{
		try
		{
			if(module_name != null && !module_name.trim().equals(""))
				return module_name;
			else if(driver_name != null && !driver_name.trim().equals(""))
				return driver_name;
			else if(alt_name != null && !alt_name.trim().equals(""))
				return alt_name;
			else if(dump_file_name != null && !dump_file_name.trim().equals(""))
				return dump_file_name;
			
			else return "driver - name unknown"; 
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_module_name");
		}
		
		return "* module *";
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
				jta.append("\nDriver: " + this.get_module_name() + "\n" + driver.UNDERLINE);
			
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
	
	
	public boolean write_manifest(PrintWriter pw, String header)
	{
		try
		{
			/////////////////////////////////////////////////////////
			//
			// particulars
			//
			////////////////////////////////////////////////////////
			driver.write_manifest_entry(pw, header, "driver_name", driver_name);
			driver.write_manifest_entry(pw, header, "module_name", module_name);
			driver.write_manifest_entry(pw, header, "alt_name", alt_name);
			driver.write_manifest_entry(pw, header, "module_base_module_dump", module_base_module_dump);
			driver.write_manifest_entry(pw, header, "offset_modules", offset_modules);
			driver.write_manifest_entry(pw, header, "offset_modscan", offset_modscan);
			driver.write_manifest_entry(pw, header, "dump_file_name", dump_file_name);
			driver.write_manifest_entry(pw, header, "size_V", size_V);
			driver.write_manifest_entry(pw, header, "file_path_from_memory", file_path_from_memory);
			driver.write_manifest_entry(pw, header, "offset_driverscan", offset_driverscan);
			driver.write_manifest_entry(pw, header, "num_ptr", num_ptr);
			driver.write_manifest_entry(pw, header, "num_handle", num_handle);
			driver.write_manifest_entry(pw, header, "start", start);
			driver.write_manifest_entry(pw, header, "service_key", service_key);
			driver.write_manifest_entry(pw, header, "size_P", size_P);
			driver.write_manifest_entry(pw, header, "start_io", start_io);

			/////////////////////////////////////////////////////////
			//
			// fle_attributes
			//
			////////////////////////////////////////////////////////
			if(this.fle_attributes != null)
			{
				pw.println(Driver.END_OF_ENTRY_MINOR);
				this.fle_attributes.write_manifest_entry(pw, header + "\t file_attr\t ", null);				
			}
			
			/////////////////////////////////////////////////////////
			//
			// list_driver_irp
			//
			////////////////////////////////////////////////////////
			if(list_driver_irp != null && list_driver_irp.size() > 0)
			{								
				for(Node_Driver_IRP node : list_driver_irp)
				{
					if(node == null)
						continue;
					
					pw.println(Driver.END_OF_ENTRY_MINOR);
					
					node.write_manifest(pw, header);
				}
			}
			
			
			/////////////////////////////////////////////////////////
			//
			// tree_callbacks
			//
			////////////////////////////////////////////////////////
			if(tree_callbacks != null && !tree_callbacks.isEmpty())
			{
				pw.println(Driver.END_OF_ENTRY_MINOR);
				for(Node_Generic node : tree_callbacks.values())
				{
					if(node == null)
						continue;
					
					//pw.println(Driver.END_OF_ENTRY_MINOR);
					
					node.write_manifest_as_single_line(pw, header + "\t callback", "\t");
				}
			}			
			
			/////////////////////////////////////////////////////////
			//
			// tree_timers
			//
			////////////////////////////////////////////////////////
			if(tree_timers != null && !tree_timers.isEmpty())
			{
				pw.println(Driver.END_OF_ENTRY_MINOR);
				
				for(Node_Generic node : tree_timers.values())
				{
					if(node == null)
						continue;

					//pw.println(Driver.END_OF_ENTRY_MINOR);

					node.write_manifest_as_single_line(pw, header + "\t timer", "\t");
				}
			}
			
			
			/////////////////////////////////////////////////////////
			//
			// tree_unloaded_modules
			//
			////////////////////////////////////////////////////////
			if(tree_unloaded_modules != null && !tree_unloaded_modules.isEmpty())
			{
				pw.println(Driver.END_OF_ENTRY_MINOR);
				
				for(Node_Generic node : tree_unloaded_modules.values())
				{
					if(node == null)
						continue;

					node.write_manifest_as_single_line(pw, header + "\t unloaded_module", "\t");
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
	
	
	public boolean import_manifest_line_entry(String line_entry, String []arr, String key, String value, Advanced_Analysis_Director DIRECTOR)
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
			
			//
			//Particulars
			//
			if(key.equals("driver_name"))
			{
				driver_name = value;					
			}
			else if(key.equals("module_name"))  module_name = value;
			else if(key.equals("alt_name"))  alt_name = value;
			else if(key.equals("module_base_module_dump"))  module_base_module_dump = value;
			else if(key.equals("offset_modules"))  offset_modules = value;
			else if(key.equals("offset_modscan"))  offset_modscan = value;
			else if(key.equals("dump_file_name"))  dump_file_name = value;
			else if(key.equals("size_v"))  size_V = value;
			else if(key.equals("file_path_from_memory"))  file_path_from_memory = value;
			else if(key.equals("offset_driverscan"))  offset_driverscan = value;
			else if(key.equals("num_ptr"))  num_ptr = value;
			else if(key.equals("num_handle"))  num_handle = value;
			else if(key.equals("start"))  start = value;
			else if(key.equals("service_key"))  service_key = value;
			else if(key.equals("size_p"))  size_P = value;
			else if(key.equals("start_io"))  start_io = value;
			
			//
			//fle_attributes
			//
			else if(key.startsWith("file_attr"))  
			{
				if(this.fle_attributes == null)
					this.fle_attributes = new FileAttributeData(this);
												
				fle_attributes.import_manifest_entry(key, value, line_entry);
			}
			
			//
			//Driver IRP Entries
			//
			else if(key.equals("driver_irp_start"))  
			{
				node_driver_irp_import_manifest = new Node_Driver_IRP(this);
				
				if(this.list_driver_irp == null)
					this.list_driver_irp = new LinkedList<Node_Driver_IRP>();
					
				node_driver_irp_import_manifest.index = this.list_driver_irp.size();	
				this.list_driver_irp.add(node_driver_irp_import_manifest);
				
				//link to IRP hook
				if(driver_name != null && !director.tree_DRIVER_IRP_HOOK.containsKey(this.driver_name.toLowerCase()) && driver_name.trim().length() > 0)
					director.tree_DRIVER_IRP_HOOK.put(this.driver_name.toLowerCase().trim(), this);
			
				else if(this.module_name != null && !director.tree_DRIVER_IRP_HOOK.containsKey(this.module_name.toLowerCase()) && module_name.trim().length() > 0)
					director.tree_DRIVER_IRP_HOOK.put(this.module_name.toLowerCase().trim(), this);

				//set the value
				node_driver_irp_import_manifest.driver_irp_start = value;
			}
			else if(key.startsWith("driver_irp_size"))
			{
				node_driver_irp_import_manifest.driver_irp_size = value;
			}

			else if(key.startsWith("driver_irp_start_io"))
			{
				node_driver_irp_import_manifest.driver_irp_start_io = value;
			}
			
			else if(key.startsWith("list_irp_entries"))
			{
				if(node_driver_irp_import_manifest.list_irp_entries == null)
					node_driver_irp_import_manifest.list_irp_entries = new LinkedList<String>();
				
				node_driver_irp_import_manifest.list_irp_entries.add(line_entry.substring("list_irp_entries".length()).trim());
			}
			
			
			//
			//callback
			//
			else if(key.equals("callback"))  
			{
				//driver_module	 callback	 	type: 	GenericKernelCallback	callback: 	0xfffff8800100c3d0	module_name: 	cng.sys	details: 	-
				
				line_entry = line_entry.substring(line_entry.indexOf("callback") + "callback".length()+1).trim();
				
				String [] array = line_entry.split("\t");
				
				if(array == null || array.length < 2)
					return false;
				
				Node_Generic callback = new Node_Generic("callbacks");
				
				callback.node_driver = this;
				
				if(director.tree_CALLBACKS == null)
					director.tree_CALLBACKS = new TreeMap<String, Node_Driver>();
					
				if(this.tree_callbacks == null)
					this.tree_callbacks = new TreeMap<String, Node_Generic>();
				
				director.tree_CALLBACKS.put(module_name_without_extension, this);
					
				for(int i = 0; i < array.length; i+=2)
				{
					try
					{
						key = array[i].toLowerCase().trim();
						value = array[i+1].trim();
						
						if(key.startsWith("type"))
							callback.type = value;
						else if(key.startsWith("callback"))
							callback.callback = value;
						else if(key.startsWith("module_name"))
							callback.module_name = value;
						else if(key.startsWith("detail"))
							callback.details = value;
						else
							callback.import_manifest_line_entry(line_entry, array, key, value, DIRECTOR);
						
					}
					catch(Exception e)
					{
						continue;
					}
				}
				
				//link
				String link_key = callback.callback + " " + callback.type;
				tree_callbacks.put(link_key, callback);
				
				
			}
			
			
			//
			//timer
			//
			else if(key.equals("timer"))  
			{				
				line_entry = line_entry.substring(line_entry.indexOf("timer") + "timer".length()+1).trim();
				
				String [] array = line_entry.split("\t");
				
				if(array == null || array.length < 2)
					return false;
				
				Node_Generic timer = new Node_Generic("timers");
				
				timer.node_driver = this;
				
				if(director.tree_TIMERS == null)
					director.tree_TIMERS = new TreeMap<String, Node_Driver>();
					
				if(this.tree_timers == null)
					this.tree_timers = new TreeMap<String, Node_Generic>();
				
				director.tree_TIMERS.put(module_name_without_extension, this);
					
				for(int i = 0; i < array.length; i+=2)
				{
					try
					{
						key = array[i].toLowerCase().trim();
						value = array[i+1].trim();
						
						if(key.startsWith("module_name"))
							timer.module_name = value;
						else if(key.startsWith("offset_v"))
						{
							timer.offset_v = value;
							tree_timers.put(value,  timer);
						}
						else if(key.startsWith("due_time"))
							timer.due_time = value;
						else if(key.startsWith("period_ms"))
							timer.period_ms = value;
						else if(key.startsWith("signaled"))
							timer.signaled = value;
						else if(key.startsWith("routine"))
							timer.routine = value;
						
						else
							timer.import_manifest_line_entry(line_entry, array, key, value, DIRECTOR);
						
						
					}
					catch(Exception e)
					{
						continue;
					}
				}
				
				
			}
			
			//
			//unloaded_module
			//
			else if(key.equals("unloaded_module"))  
			{				
				line_entry = line_entry.substring(line_entry.indexOf("unloaded_module") + "unloaded_module".length()+1).trim();
				
				String [] array = line_entry.split("\t");
				
				if(array == null || array.length < 2)
					return false;
				
				Node_Generic node = new Node_Generic("unloadedmodules");
				
				node.node_driver = this;
				
				if(director.tree_UNLOADED_MODULES == null)
					director.tree_UNLOADED_MODULES = new TreeMap<String, Node_Driver>();
				
				director.tree_UNLOADED_MODULES.put(module_name_without_extension, this);
					
				if(this.tree_unloaded_modules == null)
					this.tree_unloaded_modules = new TreeMap<String, Node_Generic>();
				
									
				for(int i = 0; i < array.length; i+=2)
				{
					try
					{
						key = array[i].toLowerCase().trim();
						value = array[i+1].trim();
																								
						node.import_manifest_line_entry(line_entry, array, key, value, DIRECTOR);												
					}
					catch(Exception e)
					{
						continue;
					}
				}
				
				
				String node_key = node.start_address + " " + node.end_address;
				this.tree_unloaded_modules.put(module_name_without_extension, node);
				
				
			}
			
			
			
			
			
			
			
			
			
			
			
			
			
			
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
	
	
	/**
	 * override
	 */
	public String toString()
	{
		try
		{
			String value = "driver module_name: " + this.module_name;
			
			if(service_key != null)
				value = value + "\tservice_key: " + service_key;
			
			if(offset_driverscan != null)
				value = value + "\toffset_driverscan: " + offset_driverscan;
			
			if(start != null)
				value = value + "\tstart: " + start;
			
			if(size_P != null)
				value = value + "\tsize_P: " + size_P;
			
			
						
			
			return  value;			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		return "* * * " + this.driver_name;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
