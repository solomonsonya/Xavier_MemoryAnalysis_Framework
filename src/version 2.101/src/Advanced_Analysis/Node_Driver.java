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
	
	
	
	
	
	
	
	
	
}
