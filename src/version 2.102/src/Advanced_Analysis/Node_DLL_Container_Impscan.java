/**
 * This is a DLL container node, e.g. ADVAPI32.dll that holds a list of all import functions called by a specific process
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import java.io.*;
import java.util.*;

import Advanced_Analysis.*;
import Driver.*;

public class Node_DLL_Container_Impscan 
{
	public static final String myClassName = "Node_DLL_Container_Impscan";
	public static volatile Driver driver = new Driver();
	
	public volatile Node_Process process = null;
	
	/**case sensitive*/
	public volatile String module_name = "";
	public volatile String module_name_lower = "";
	
	public volatile TreeMap<String, Node_Generic> tree_impscan_functions = new TreeMap<String, Node_Generic>();
	
		
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
					dll.process_import_function(IAT, call, FUNCTION_NAME);
				else
				{
					//
					//link to process's import tree
					//
					process.tree_impscan_DLL_containers.put(module_name_lower, this);

					
					//process entry					
					this.process_import_function(IAT, call, FUNCTION_NAME);
				}
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Node_DLL_Impscan", e);
		}
	}
	
	public boolean process_import_function(String IAT, String call, String function_name)
	{
		try
		{
			if(function_name == null || function_name.trim().equals(""))
				return false;
			
			function_name = function_name.trim();						
			String function_name_lower = function_name.toLowerCase().trim();
			
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
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
