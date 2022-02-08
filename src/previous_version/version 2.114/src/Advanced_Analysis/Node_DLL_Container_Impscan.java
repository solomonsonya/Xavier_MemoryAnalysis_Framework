/**
 * This is a DLL container node, e.g. ADVAPI32.dll that holds a list of all import functions called by a specific process
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import java.io.*;
import java.util.*;

import Advanced_Analysis.*;
import Driver.*;
import Interface.JTextArea_Solomon;

public class Node_DLL_Container_Impscan 
{
	public static final String myClassName = "Node_DLL_Container_Impscan";
	public static volatile Driver driver = new Driver();
	
	public volatile Node_Process process = null;
	

	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false;
	
	/**case sensitive*/
	public volatile String module_name = "";
	public volatile String module_name_lower = "";
	
	public volatile TreeMap<String, Node_Generic> tree_impscan_functions = new TreeMap<String, Node_Generic>();
	
	public volatile TreeMap<String, LinkedList<Node_Process>> tree_import_function_mapped_to_importing_process = new TreeMap<String, LinkedList<Node_Process>>();
	
		
	public Node_DLL_Container_Impscan(Node_Process PROCESS, String MODULE_NAME, String IAT, String call, String FUNCTION_NAME)
	{
		try
		{
			process = PROCESS;
			module_name = MODULE_NAME;
			
			if(module_name != null && !module_name.trim().equals(""))
			{
				module_name = module_name.trim();
				module_name_lower = module_name.toLowerCase().trim();
				
				//setermine if module exists
				Node_DLL_Container_Impscan dll = null;
				
				if(process.tree_impscan_DLL_containers.containsKey(module_name_lower))
					dll = process.tree_impscan_DLL_containers.get(module_name_lower);
				
				if(dll != null)
					dll.process_import_function(IAT, call, FUNCTION_NAME, PROCESS);
				else
				{
					//
					//link to process's import tree
					//
					process.tree_impscan_DLL_containers.put(module_name_lower, this);

					
					//process entry					
					this.process_import_function(IAT, call, FUNCTION_NAME, PROCESS);
				}
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Node_DLL_Impscan", e);
		}
	}
	
	public boolean process_import_function(String IAT, String call, String function_name, Node_Process PROCESS)
	{
		try
		{
			if(function_name == null || function_name.trim().equals(""))
				return false;
			
			function_name = function_name.trim();						
			String function_name_lower = function_name.toLowerCase().trim();
			
			//map import function to importing process
			LinkedList<Node_Process> list_processes = null;
			
			////////////////////////////////////////////////////////////////
			//
			// link process to import function
			//
			////////////////////////////////////////////////////////////////
			if(PROCESS != null)
			{
				if(this.tree_import_function_mapped_to_importing_process.containsKey(function_name_lower))
					list_processes = this.tree_import_function_mapped_to_importing_process.get(function_name_lower);
				
				if(list_processes == null)
				{
					//create list
					list_processes = new LinkedList<Node_Process>();
					
					//link list to tree
					this.tree_import_function_mapped_to_importing_process.put(function_name_lower, list_processes);
				}
				
				//put process
				if(list_processes!= null && !list_processes.contains(PROCESS))
					list_processes.add(PROCESS);
			}
			
			////////////////////////////////////////////////////////////////
			//
			// store/update particulars regarding specific import fcn
			//
			////////////////////////////////////////////////////////////////
			
			Node_Generic import_function = null;
			
			if(this.tree_impscan_functions.containsKey(function_name_lower))
			{
				try
				{
					Node_Generic node = tree_impscan_functions.get(function_name_lower);
					
					if(call.trim().equals(node.call))
					{
						//just add additional entry to IAT
						if(IAT != null && !IAT.trim().equals("") && node.IAT != null && !node.IAT.trim().equals("") && !node.IAT.contains(IAT))
							node.IAT = node.IAT + ", " + IAT;
					}
					else
					{
					
						if(process != null)
							driver.sop("[impscan] NOTE: duplicate import function [" + function_name + "] found for DLL [" + this.module_name + "] on process " + this.process.get_process_html_header());
						else
							driver.sop("[impscan] NOTE: duplicate import function [" + function_name + "] found for DLL [" + this.module_name + "]");
					}
					
					
				}
				catch(Exception e){}
				
				
				return false;
			}
			
			//otw, create new node!
			import_function = new Node_Generic("impscan");
			
			try	{	import_function.IAT = IAT.trim();} catch(Exception e){}
			try	{	import_function.call = call.trim();} catch(Exception e){}
			try	{	import_function.DLL_Container_Impscan = this;} catch(Exception e){}
			try	{	import_function.function = function_name.trim();} catch(Exception e){}
			try	{	import_function.function_name_lower = function_name.toLowerCase().trim();} catch(Exception e){}
			
			//
			//link!
			//
			this.tree_impscan_functions.put(function_name_lower, import_function);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_function", e);
		}
		
		return false;
	}
	
	
	
	public boolean write_tree_imports(PrintWriter pw)
	{
		try
		{
			if(this.tree_impscan_functions == null || this.tree_impscan_functions.size() < 1)
				return false;
			
			//write module name
			pw.println("\t\t\t" +  "{ \"name\": \"" +  driver.normalize_html(this.module_name).replace("\\", "\\\\") + "\" , \"children\": [");

			
			if(tree_impscan_functions != null &&tree_impscan_functions.size() > Node_Process.MAX_TREE_NODE_COUNT)
			{
				int count = 0;				
				pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
				
				for(Node_Generic import_function : tree_impscan_functions.values())
				{															
					if(count % Node_Process.MAX_TREE_NODE_COUNT == 0 && count > 0)
					{
						pw.println("\t\t\t" +  "]},");
						
						pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
					}
					
					if(import_function == null || import_function.function_name_lower == null || import_function.function_name_lower.trim().equals(""))
						continue;
					
					driver.write_EXPANDED_node_ENTRY(import_function.function, "IAT: " + import_function.IAT + "       Call:" + import_function.call, pw);
					
					++count;
				}
				
				pw.println("\t\t\t" +  "]},");								
			}
			
			else
			{							
				//write function names under each module name
				for(Node_Generic import_function : tree_impscan_functions.values())
				{
					try
					{
						if(import_function == null || import_function.function_name_lower == null || import_function.function_name_lower.trim().equals(""))
							continue;
						
						driver.write_EXPANDED_node_ENTRY(import_function.function, "IAT: " + import_function.IAT + "       Call:" + import_function.call, pw);
						
					}
					catch(Exception e)
					{
						continue;
					}
				} //end for
			}
			
			//write module name closure
			pw.println("\t\t\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_tree_imports", e);
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
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(module_name, "module_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				
			if(this.tree_impscan_functions != null)
			{
				for(Node_Generic node : this.tree_impscan_functions.values())
				{
					if(node == null)
						continue;
					
					node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, "Impscan");
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
	
	
	
	
	
	/**
	 * continuation mtd
	 * @param pw
	 * @param key
	 * @param value
	 * @return
	 */
	public boolean write_manifest(PrintWriter pw, String header, String delimiter, boolean include_underline)
	{
		try
		{
			if(pw == null)
				return false;	
			
			delimiter = delimiter + " ";
			
			if(tree_impscan_functions == null || tree_impscan_functions.isEmpty())
				return false;
			
			for(Node_Generic node : tree_impscan_functions.values())
			{
				driver.write_manifest_entry(pw, header, 	"module_name " + delimiter + module_name + delimiter + 
															"module_name_lower " + delimiter + module_name_lower + delimiter + 
															node.get_manifest_impscan("", delimiter)												
						);
			}
							 			
			

			if(include_underline)
				pw.println(Driver.END_OF_ENTRY_MINOR);

			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
