/**
 * Imported DLL has improrted functions. 
 * 
 * This node keeps track of the Imported funciton name, as well as the parent DLL, as well as the importing Processes of the DLL
 * 
 * @author Solomon Sonya
 */


package Advanced_Analysis;

import java.io.*;
import java.util.LinkedList;
import java.util.TreeMap;

import Driver.*;
import Driver.FileAttributeData;
import Interface.JTextArea_Solomon;


public class Node_Import_DLL_Function 
{	
	public static final String myClassName = "Node_Import_DLL_Function";
	public static volatile Driver driver = new Driver();
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false; 
	
	//
	//dependencies
	//
	public volatile String function_name = null;
	public volatile Node_DLL DLL = null;
	
	
	//
	//impscan
	//
	public volatile String IAT = null;
	public volatile String call = null;
	public volatile String module_name = null;
	public volatile String function = "";
	
	
	
	
	public volatile TreeMap<Integer, Node_Process> tree_process = new TreeMap<Integer, Node_Process>();
	
	public Node_Import_DLL_Function()
	{
		try
		{
			
		}
		catch(Exception e){}
	}
	
	public Node_Import_DLL_Function(String func_name, Node_DLL dll, Node_Process process)
	{
		try
		{
			function_name = func_name;
			DLL = dll;
			
			String function_name_lower = function_name.toLowerCase().trim();
			
			//link funciton name
			if(DLL != null)
			{
				//ensure not duplicate funciton name
				if(DLL.tree_import_function_table_dependencies.containsKey(function_name_lower))
					DLL.tree_import_function_table_dependencies.get(function_name_lower).link_process(process);
				else
				{
					//new, link funciton name
					DLL.tree_import_function_table_dependencies.put(function_name_lower, this);
					
					//link process
					link_process(process);
				}
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	/**
	 * only used for dependencies
	 * */
	public boolean link_process(Node_Process process)
	{
		try
		{
			if(process == null)
				return false;
			
			if(!this.tree_process.containsKey(process.PID))
				this.tree_process.put(process.PID, process);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "link_process", e);
		}
		
		return false;
	}

	
	
	
	
	
	
	
	
	
	
	
	public boolean store_function()
	{
		try
		{
			//get dll
			
			//get process
			
			//get dll node's import_call_tree and store e.g. dll.import_function_call_tree.put(call_address, function_name)
			
			//link all processes to the same function name
			//--> dll.tree_import_function_name.put(function_name, LinkedList<Node_Process> - add process to the linked_list
			
			
			//get process node's IAT_address and store this node at process' tree e.g. process.tree_IAT.put(this.IAT, this)
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "store_function", e);
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
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(function_name, "function_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(IAT, "IAT", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(call, "call", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(module_name, "module_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(function, "function", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				
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
