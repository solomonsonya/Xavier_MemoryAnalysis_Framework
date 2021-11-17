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
	
	
	
	
	
	
	
}
