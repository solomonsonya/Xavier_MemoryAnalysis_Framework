/**
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.border.BevelBorder;

import Advanced_Analysis.Analysis_Plugin.*;

public class Node_Generic 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_Generic";
	
	public volatile String plugin_name = null;
	
	public volatile LinkedList<String> list_details = null;
	
	public volatile String pid = null;
	public volatile String process_name = null;
	public volatile Node_Process process = null;
	public volatile Node_DLL dll = null;
	
	//
	//GDI Timers
	//
	public volatile String session = null;
	public volatile String handle = null;
	public volatile String object = null;
	public volatile String thread = null;
	public volatile String process_details = null;
	public volatile String nID = null;
	public volatile String rate_ms = null;
	public volatile String countdown_ms = null;
	public volatile String function = null;
	
	//
	//Callbacks
	//
	public volatile Node_Driver node_driver = null;
	public volatile String type = null;
	public volatile String callback = null;
	public volatile String module_name = null;
	public volatile String details = null;
	
	//
	//timers
	//
	public volatile String offset_v = null;
	public volatile String due_time = null;
	public volatile String period_ms = null;
	public volatile String signaled = null;
	public volatile String routine = null;
	
	//
	//Unloaded Modules
	//
	public volatile String start_address = null;
	public volatile String end_address = null;
	public volatile String date = null;
	public volatile String time = null;
	
	//
	//userassist
	//
	public volatile String reg_binary = null;
	public volatile String raw_data = null;
	public volatile String id = null;
	public volatile String count = null;
	public volatile String last_updated = null;
	
	//
	//vadinfo
	//
	public volatile String offset = null;
	public volatile String name = null;
	public volatile String path = null;
	
	//
	//deskscan
	//
	public volatile String desktop_offset = null;
	public volatile String next = null;
	public volatile String session_id = null;
	public volatile String desktop_info = null;
	public volatile String size = null;
	public volatile String fshooks = null;
	public volatile String spwnd = null;
	public volatile String windows = null;
	public volatile String heap = null;
	public volatile String limit = null;
	public volatile String base = null;
	/**stores processes linked to this desktop*/
	public volatile TreeMap<Integer, Node_Process> tree_process = null;
	
	//
	//impscan
	//
	/**e.g. base_address for impscan*/
	public volatile String impscan_start_address = null;	
	public volatile String impscan_end_address = null;
	public volatile String IAT = null;
	public volatile String call = null;
	public volatile Node_DLL_Container_Impscan DLL_Container_Impscan = null;
	public volatile String function_name_lower = null;
	
	//
	//filescan
	//
	public volatile String offset_p = null;
	public volatile String num_ptr = null;
	public volatile String num_hnd = null;
	public volatile String access = null;
	public volatile String path_name = null;	
	
	//
	//File XREF
	//
	public volatile String file_name = null;
	public volatile JCheckBox jcb = null;
	public volatile File fle = null;
	public volatile Analysis_Plugin_DumpFiles plugin_dumpfile = null;
	public volatile Analysis_Plugin_memdump plugin_execution = null;
	
	//
	//DLLDUMP
	//Process(V)         Name                 Module Base        Module Name          Result
	//------------------ -------------------- ------------------ -------------------- ------
	//0xfffffa800148f040 smss.exe             0x0000000047ef0000 smss.exe             OK: module.248.3f68f040.47ef0000.dll
	//0xfffffa800148f040 smss.exe             0x0000000077c90000 ntdll.dll            OK: module.248.3f68f040.77c90000.dll
	public volatile String process_offset_V = null;
	public volatile String module_base_address = null;
	public volatile String process_offset_P_trimmed = null;
	public volatile String module_base_address_trimmed = null;
	public volatile String module_basse_address_trimmed = null;
	public volatile int PID = -1;
	
	public Node_Generic(String PLUGIN_NAME)
	{
		try
		{
			plugin_name = PLUGIN_NAME;
			
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
			pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html("READY").replace("\\", "\\\\") + "\" , \"children\": [");

			//driver.write_node_ENTRY("SID: ", this.sid, pw);
			
			
			pw.println("\t\t" +  "]},");//end process information			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_information", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	public boolean write_node_information_from_list(String title, PrintWriter pw)
	{
		try
		{
			pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html(title).replace("\\", "\\\\") + "\" , \"children\": [");

			if(this.list_details == null || this.list_details.size() < 1)
				return false;
			
			for(String entry : this.list_details)
			{
				driver.write_node_ENTRY("", entry, pw);	
			}						
			
			pw.println("\t\t" +  "]},");			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_information_SHUTDOWNTIME", e);
		}
		
		return false;
	}
	
	
	
	public boolean write_node_CALLBACKS(PrintWriter pw, boolean include_header)
	{
		try
		{
			if(include_header)
				pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html(type).replace("\\", "\\\\") + "\" , \"children\": [");
			
			driver.write_node_ENTRY("Type: ", type, pw);
			driver.write_node_ENTRY("Callback: ", callback, pw);
			driver.write_node_ENTRY("Module: ", module_name, pw);
			
			if((details == null || details.trim().equals("-")) && this.node_driver != null && this.node_driver.file_path_from_memory != null && !this.node_driver.file_path_from_memory.trim().equals("-"))
				driver.write_node_ENTRY("Details: ", node_driver.file_path_from_memory, pw);
			else
				driver.write_node_ENTRY("Details: ", details, pw);
			
			if(include_header)
				pw.println("\t\t\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_CALLBACKS", e);
		}
		
		return false;
	}
	
	
	public boolean write_node_UNLOADED_MODULES(PrintWriter pw, boolean include_header)
	{
		try
		{
			if(include_header)
				pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("Start: " + this.start_address).replace("\\", "\\\\") + "\" , \"children\": [");
			
			driver.write_node_ENTRY("Module: ", module_name, pw);
			driver.write_node_ENTRY("Start Address: ", start_address, pw);
			driver.write_node_ENTRY("End Address: ", end_address, pw);
			driver.write_node_ENTRY("Date: ", date, pw);
			driver.write_node_ENTRY("Time: ", time, pw);
			
			if(this.node_driver != null && this.node_driver.file_path_from_memory != null && !this.node_driver.file_path_from_memory.trim().equals("-"))
				driver.write_node_ENTRY("Path: ", node_driver.file_path_from_memory, pw);
			
			if(include_header)
				pw.println("\t\t\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_CALLBACKS", e);
		}
		
		return false;
	}
	
	
	public boolean write_node_Timers(PrintWriter pw, boolean include_header)
	{
		try
		{
			if(include_header)
				pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("Offset (V): " + this.offset_v).replace("\\", "\\\\") + "\" , \"children\": [");
			
			driver.write_node_ENTRY("Offset(V): ", offset_v, pw);
			driver.write_node_ENTRY("Due Time: ", this.due_time, pw);
			driver.write_node_ENTRY("Period (ms): ", this.period_ms, pw);
			driver.write_node_ENTRY("Signaled: ", signaled, pw);
			driver.write_node_ENTRY("Routine: ", routine, pw);
			driver.write_node_ENTRY("Module: ", this.module_name, pw);
			
			if(this.node_driver != null && this.node_driver.file_path_from_memory != null && !this.node_driver.file_path_from_memory.trim().equals("-"))
				driver.write_node_ENTRY("Path: ", node_driver.file_path_from_memory, pw);
			
			if(include_header)
				pw.println("\t\t\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_Timers", e);
		}
		
		return false;
	}
	
	
	
	public boolean write_node_User_Assist(String title, PrintWriter pw)
	{
		try
		{
			if(title != null && title.contains("\\"))
				title = title.substring(title.lastIndexOf("\\")+1).trim();
			
			pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html(title).replace("\\", "\\\\") + "\" , \"children\": [");

			this.driver.write_node_ENTRY("REG_BINARY: ", this.reg_binary, pw);
			this.driver.write_node_ENTRY("ID: ", this.id, pw);
			this.driver.write_node_ENTRY("Count: ", this.count, pw);
			this.driver.write_node_ENTRY("Last Updated: ", this.last_updated, pw);
			this.driver.write_node_ENTRY("Raw Data: ", this.raw_data, pw);
			
			pw.println("\t\t" +  "]},");			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_User_Assist", e);
		}
		
		return false;
	}
	
	
	
	
	/**
	 * 	Offset(P)            #Ptr   #Hnd Access Name
	 *	------------------ ------ ------ ------ ----
	 * 	0x000000003e83e070      1      0 R--rw- \Device\HarddiskVolume2\ProgramData\Microsoft\Windows\Start Menu\Programs\WinRAR\Console RAR manual.lnk
	 * @param line
	 * @return
	 */
	public boolean process_file_scan_entry(String line, boolean memory_image_is_WINDOWS)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return false;
			
			line = line.trim();
			
			String [] arr = line.split(" ");
			
			for(String token : arr)
			{
				token = token.trim();
				
				if(token.equals(""))
					continue;
				
				if(this.offset_p == null)
					offset_p = token;
				else if(this.num_ptr == null)
					this.num_ptr = token;
				else if(this.num_hnd == null)
					this.num_hnd = token;
				else if(this.access == null)
					this.access = token;
				else if(path_name == null)
					path_name = token;
				else
					this.path_name = path_name + " " + token;				
			}
			
			if(path_name != null)
				path_name = path_name.trim();
			
			//
			//SET FILE NAME
			//
			if(path_name == null)
			{
				file_name = "file_" + System.nanoTime();
				return true;
			}
			
			String path = "\\";
			
			if(!memory_image_is_WINDOWS)
				path = "/";
			
			try	{	file_name = path_name.substring(path_name.lastIndexOf(path)).trim();	}
			catch(Exception e)
			{
				//try opposite path
				if(path.equals("\\"))
					path = "/";
				else
					path = "\\";
				
				try	{	file_name = path_name.substring(path_name.lastIndexOf(path)).trim();	}
				
				catch(Exception eee)
				{
					file_name = path_name;
				}
			}
			
			file_name = driver.normalize_file_name(file_name);
			
			//
			//create jcheckbox
			//
			this.jcb = new JCheckBox("<html>filescan - " + file_name + "  - <b>" + this.offset_p + "</b></html>", false);
			this.jcb.setToolTipText("<html><b> Offset (P): </b>" + this.offset_p + "  <b> Path: </b>" + this.path_name + "</html>");
			//jcb_file_dump_entry.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_file_scan", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
