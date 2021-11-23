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
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false;
	
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
			
			///////////////////////////////////////////////////////////////////////
			//
			//VAD Info
			//
			//////////////////////////////////////////////////////////////////////
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset, "Offset", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(name, "Name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(path, "Path", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);

			///////////////////////////////////////////////////////////////////////
			//
			//Search File
			//
			//////////////////////////////////////////////////////////////////////
			if(fle != null)
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle.getCanonicalPath(), "File", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			
			///////////////////////////////////////////////////////////////////////
			//
			//File Attributes
			//
			//////////////////////////////////////////////////////////////////////
//			if(this.fle_attributes != null)
//			{
//				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.creation_date, "File Mem Dump Creation Date", search_string, search_string_lower, jta, searching_proces);
//				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.extension, "File Mem Dump Extension", search_string, search_string_lower, jta, searching_proces);
//				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.file_name, "File Mem Dump Name", search_string, search_string_lower, jta, searching_proces);
//				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_md5, "File Hash - MD5", search_string, search_string_lower, jta, searching_proces);
//				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_sha256, "File Hash - Sha256", search_string, search_string_lower, jta, searching_proces);
//				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_accessed, "File Mem Dump Last Accessed", search_string, search_string_lower, jta, searching_proces);
//				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_modified, "File Mem Dump Last Modified", search_string, search_string_lower, jta, searching_proces);
//				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.size, "File Mem Dump Size", search_string, search_string_lower, jta, searching_proces);
//			}
			
			///////////////////////////////////////////////////////////////////////
			//
			//List Details
			//
			//////////////////////////////////////////////////////////////////////
			if(list_details != null)
			{
				for(String detail : list_details)
				{
					XREF_SEARCH_HIT_FOUND |= this.check_value(detail, "Details", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				}
			}
			
			//
			//GDI Timers
			//
			XREF_SEARCH_HIT_FOUND |= this.check_value(session, "session", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(handle, "handle", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(object, "object", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(thread, "thread", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(process_details, "process_details", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(nID, "nID", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(rate_ms, "rate_ms", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(countdown_ms, "countdown_ms", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(function, "function", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);

			//
			//Callbacks
			//
			XREF_SEARCH_HIT_FOUND |= this.check_value(type, "type", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(callback, "callback", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(module_name, "module_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(details, "details", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);

			//
			//timers
			//
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset_v, "offset_v", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(due_time, "due_time", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(period_ms, "period_ms", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(signaled, "signaled", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(routine, "routine", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);

			//
			//Unloaded Modules
			//
			XREF_SEARCH_HIT_FOUND |= this.check_value(start_address, "start_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(end_address, "end_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(date, "date", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(time, "time", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);

			//
			//userassist
			//
			XREF_SEARCH_HIT_FOUND |= this.check_value(reg_binary, "reg_binary", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(raw_data, "raw_data", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(id, "id", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(count, "count", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(last_updated, "last_updated", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);

			//

			//
			//deskscan
			//
			XREF_SEARCH_HIT_FOUND |= this.check_value(desktop_offset, "desktop_offset", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(next, "next", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(session_id, "session_id", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(desktop_info, "desktop_info", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(size, "size", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(fshooks, "fshooks", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(spwnd, "spwnd", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(windows, "windows", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(heap, "heap", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(limit, "limit", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(base, "base", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);



			//
			//impscan
			//
			XREF_SEARCH_HIT_FOUND |= this.check_value(impscan_start_address, "impscan_start_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(impscan_end_address, "impscan_end_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(IAT, "IAT", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(call, "call", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(function_name_lower, "function_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);

			//
			//filescan
			//
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset_p, "offset(p)", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(num_ptr, "num_ptr", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(num_hnd, "num_hnd", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(access, "access", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(path_name, "path_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);


			//
			//DLLDUMP
			XREF_SEARCH_HIT_FOUND |= this.check_value(process_offset_V, "process_offset(V)", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(module_base_address, "module_base_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(process_offset_P_trimmed, "process_offset(P)", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(module_base_address_trimmed, "module_base_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			//XREF_SEARCH_HIT_FOUND |= this.check_value(module_basse_address_trimmed, "module_basse_address_trimmed", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value((""+PID), (""+PID), search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);

			
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
