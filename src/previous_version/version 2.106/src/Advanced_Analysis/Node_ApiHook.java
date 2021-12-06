/**
 * Environment Variables Node
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
import org.apache.commons.io.LineIterator;



public class Node_ApiHook 
{
	public static final String myClassName = "Node_ApiHook";
	public static volatile Driver driver = new Driver();
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false; 
	
	public volatile Node_Process process = null;
	public volatile Node_DLL dll = null;
	
	public volatile String hook_mode = null;			
	public volatile String hook_type = null;
	public volatile String process_line = null;
	public volatile String pid = null;
	public volatile String process_name = null;
	public volatile int PID = -1;
	public volatile String victim_module_line = null;
	public volatile String victim_module_name = null;
	public volatile String victim_module_base_address = null;
	public volatile String function = null;
	public volatile String hook_address = null;
	public volatile String hooking_module = null;	
	public volatile boolean MZ_Detected = false;
	public volatile boolean Trampoline_Initial_JMP_Detected = false;
	
	public volatile LinkedList<String> list_dissassembly_0 = null;
	public volatile LinkedList<String> list_dissassembly_1 = null;
	public volatile LinkedList<String> list_dissassembly_2 = null;
	public volatile LinkedList<String> list_dissassembly_3 = null;
	
	
	
	
	public Node_ApiHook(Node_DLL DLL, Node_Process proc, String Process_Name, String Pid, int process_ID)
	{
		try
		{
			dll = DLL;
			process = proc;		
			process_name = Process_Name;
			pid = Pid;
			PID = process_ID;
			
			if(this.process_name == null || this.process_name.trim().equals("") || this.process_name.toLowerCase().contains("unknown") || this.process_name.trim().equals("()"))
			{
				if(this.process != null)
				{
					this.process_name = process.process_name;
					this.pid = ""+ process.PID;
					this.PID = process.PID;
				}
				
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	public boolean write_hook_html(String tab, PrintWriter pw)
	{
		try
		{
			pw.println(tab + "\t" +  "{ \"name\": \"" +  driver.normalize_html("API Hook Address: " + this.hook_address).replace("\\", "\\\\") + "\" , \"children\": [");
			
			if(this.hook_mode != null && !this.hook_mode.trim().equals(""))
				pw.println(tab + "	" +  "{ \"name\": \"Hook Mode: " + driver.normalize_html(hook_mode).replace("\\", "\\\\") + "\" },");
			
			if(this.hook_type != null && !this.hook_type.trim().equals(""))
				pw.println(tab + "	" +  "{ \"name\": \"Hook Type: " + driver.normalize_html(hook_type).replace("\\", "\\\\") + "\" },");
			
			if(this.process != null)
				pw.println(tab + "	" +  "{ \"name\": \"Process: " + driver.normalize_html(process.get_process_html_header()).replace("\\", "\\\\") + "\" },");
			
			else if(this.process_name != null && !this.process_name.trim().equals(""))
				pw.println(tab + "	" +  "{ \"name\": \"Process Name: " + driver.normalize_html(this.process_line).replace("\\", "\\\\") + "\" },");
			
			if(this.victim_module_line != null && !this.victim_module_line.trim().equals(""))
				pw.println(tab + "	" +  "{ \"name\": \"Victim Module : " + driver.normalize_html(this.victim_module_line).replace("\\", "\\\\") + "\" },");
			
			if(this.function != null && !this.function.trim().equals(""))
				pw.println(tab + "	" +  "{ \"name\": \"Function : " + driver.normalize_html(function).replace("\\", "\\\\") + "\" },");
			
			if(this.hooking_module != null && !this.hooking_module.trim().equals(""))
				pw.println(tab + "	" +  "{ \"name\": \"Hooking Module : " + driver.normalize_html(hooking_module).replace("\\", "\\\\") + "\" },");						
			
			if(Trampoline_Initial_JMP_Detected)
				driver.write_node_ENTRY("* * * Trampoline Detected:", ""+this.Trampoline_Initial_JMP_Detected, pw);
			
			if(this.MZ_Detected)
				driver.write_node_ENTRY("* * * MZ Detected:", ""+this.MZ_Detected, pw);
							
			
			driver.write_node_LIST_ENTRIES("Dissassembly(0)", this.list_dissassembly_0, pw);
			driver.write_node_LIST_ENTRIES("Dissassembly(1)", this.list_dissassembly_1, pw);
			driver.write_node_LIST_ENTRIES("Dissassembly(2)", this.list_dissassembly_2, pw);
			driver.write_node_LIST_ENTRIES("Dissassembly(3)", this.list_dissassembly_3, pw);
			
			
			
			pw.println(tab + "\t" +  "]},");
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_hook_html", e);
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
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(hook_mode, "hook_mode", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(hook_type, "hook_type", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(process_line, "process_line", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(pid, "pid", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(process_name, "process_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(victim_module_line, "victim_module_line", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(victim_module_name, "victim_module_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(victim_module_base_address, "victim_module_base_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(function, "function", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(hook_address, "hook_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(hooking_module, "hooking_module", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);

			//
			//list_dissassembly_0
			//
			if(list_dissassembly_0 != null)
			{
				for(String detail : list_dissassembly_0)
				{
					XREF_SEARCH_HIT_FOUND |= this.check_value(detail, "List Disassembly 0", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				}
			}
			
			//
			//list_dissassembly_1
			//
			if(list_dissassembly_1 != null)
			{
				for(String detail : list_dissassembly_1)
				{
					XREF_SEARCH_HIT_FOUND |= this.check_value(detail, "List Disassembly 1", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				}
			}
			
			//
			//list_dissassembly_2
			//
			if(list_dissassembly_2 != null)
			{
				for(String detail : list_dissassembly_2)
				{
					XREF_SEARCH_HIT_FOUND |= this.check_value(detail, "List Disassembly 2", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				}
			}
			
			//
			//list_dissassembly_3
			//
			if(list_dissassembly_3 != null)
			{
				for(String detail : list_dissassembly_3)
				{
					XREF_SEARCH_HIT_FOUND |= this.check_value(detail, "List Disassembly 3", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
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
