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
	
	public volatile boolean I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = false;
	
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
	public volatile String raw_data_first_line = null;
	public volatile String id = null;
	public volatile String count = null;
	public volatile String focus_count = null;
	public volatile String time_focused = null;	
	public volatile String last_updated = null;
	
	//do not link these in xref search, it is just to link back to registry and hive for user assist time focused value
	public volatile Node_Registry_Hive registry_hive = null;
	public volatile Node_Registry_Key registry_key = null;
		
	
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
	
	//
	//indicate if vad_node has been printed under process vad tree  - use this to remove duplication of vad_info being printed by write_manifest
	//
	public volatile boolean printed_vad_info_node_under_process = false;
	
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
			this.driver.write_node_ENTRY("Focus Count: ", this.focus_count, pw);
			this.driver.write_node_ENTRY("Time Focused: ", this.time_focused, pw);
			this.driver.write_node_ENTRY("Last Updated: ", this.last_updated, pw);
			this.driver.write_node_ENTRY("Raw Data First Line: ", this.raw_data_first_line, pw);
			
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
			XREF_SEARCH_HIT_FOUND |= this.check_value(raw_data_first_line, "raw_data_first_line", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(id, "id", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(count, "count", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(this.focus_count, "focus_count", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(this.time_focused, "time_focused", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
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
			
			//if(searching_proces == null)
			//	return false;
			
			if(lower.contains(search_string_lower))
			{
				//
				//append via process
				//
				if(searching_proces != null)
					searching_proces.append_to_jta_XREF(container_search_name + " [" + mneumonic + "]: " + value_to_check, jta);
				
				//
				//append self e.g., search comes directly from File_XREF search structure Node_Generic
				//
				else 
				{
					if(!this.I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY && jta != null)
					{
						try {		jta.append("\n\n" + container_search_name.substring(0, container_search_name.indexOf("@")) + "\n" + driver.UNDERLINE);					}
						catch(Exception ee)		{		jta.append("\n\n" + container_search_name + "\n" + driver.UNDERLINE);}
						I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = true;
					}												
					
					//
					//write value
					//
					jta.append(container_search_name + " [" + mneumonic + "]: " + value_to_check);					
					
				}
				
				
				return true;
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "check_value", e);
		}
		
		return false;
	}
	
	public boolean write_manifest_as_single_line(PrintWriter pw, String header, String delimiter)
	{
		try
		{
			if(pw == null)
				return false;	
			
			String output = "";
			
			output = output + driver.get_trimmed_entry("pid", pid, delimiter, true, false, ":");
			if(PID > -1)	output = output + delimiter + PID;
			
			output = output + driver.get_trimmed_entry("process_name", process_name, delimiter, true, false, ":");

			//
			//GDI Timers
			//
			output = output + driver.get_trimmed_entry("session", session, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("handle", handle, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("object", object, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("thread", thread, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("process_details", process_details, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("nID", nID, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("rate_ms", rate_ms, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("countdown_ms", countdown_ms, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("function", function, delimiter, true, false, ":");

			//
			//Callbacks
			//	
			//public volatile Node_Driver node_driver = null;
			output = output + driver.get_trimmed_entry("type", type, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("callback", callback, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("module_name", module_name, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("details", details, delimiter, true, false, ":");

			//
			//timers
			//
			output = output + driver.get_trimmed_entry("offset_v", offset_v, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("due_time", due_time, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("period_ms", period_ms, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("signaled", signaled, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("routine", routine, delimiter, true, false, ":");

			//
			//Unloaded Modules
			//
			output = output + driver.get_trimmed_entry("start_address", start_address, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("end_address", end_address, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("date", date, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("time", time, delimiter, true, false, ":");

			//
			//userassist
			//
			output = output + driver.get_trimmed_entry("reg_binary", reg_binary, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("raw_data_first_line", raw_data_first_line, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("id", id, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("count", count, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("focus_count", this.focus_count, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("time_focused", this.time_focused, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("last_updated", last_updated, delimiter, true, false, ":");

			//
			//vadinfo
			//
			output = output + driver.get_trimmed_entry("offset", offset, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("name", name, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("path", path, delimiter, true, false, ":");

			//
			//deskscan
			//
			output = output + driver.get_trimmed_entry("desktop_offset", desktop_offset, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("next", next, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("session_id", session_id, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("desktop_info", desktop_info, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("size", size, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("fshooks", fshooks, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("spwnd", spwnd, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("windows", windows, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("heap", heap, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("limit", limit, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("base", base, delimiter, true, false, ":");

			//
			//impscan
			//
			output = output + driver.get_trimmed_entry("impscan_start_address", impscan_start_address, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("impscan_end_address", impscan_end_address, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("IAT", IAT, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("call", call, delimiter, true, false, ":");
			//public volatile Node_DLL_Container_Impscan DLL_Container_Impscan, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("function_name_lower", function_name_lower, delimiter, true, false, ":");

			//
			//filescan
			//
			output = output + driver.get_trimmed_entry("offset_p", offset_p, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("num_ptr", num_ptr, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("num_hnd", num_hnd, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("access", access, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("path_name", path_name, delimiter, true, false, ":");

			//
			//File XREF
			//
			output = output + driver.get_trimmed_entry("file_name", file_name, delimiter, true, false, ":");

			//
			//DLLDUMP
			//Process(V)         Name                 Module Base        Module Name          Result
			//------------------ -------------------- ------------------ -------------------- ------
			//0xfffffa800148f040 smss.exe             0x0000000047ef0000 smss.exe             OK: module.248.3f68f040.47ef0000.dll, delimiter, true, false, ":");
			//0xfffffa800148f040 smss.exe             0x0000000077c90000 ntdll.dll            OK: module.248.3f68f040.77c90000.dll, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("process_offset_V", process_offset_V, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("module_base_address", module_base_address, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("process_offset_P_trimmed", process_offset_P_trimmed, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("module_base_address_trimmed", module_base_address_trimmed, delimiter, true, false, ":");
			output = output + driver.get_trimmed_entry("module_basse_address_trimmed", module_basse_address_trimmed, delimiter, true, false, ":");
				
			//
			//file
			//
			if(this.fle != null && file_name == null)
				output = output + driver.get_trimmed_entry("fle", "/" + fle.getParentFile().getName() + "/" + fle.getName(), delimiter, true, false, ":"); 


			if(list_details != null && !list_details.isEmpty())
			{
				output = output + delimiter + "list_details";
				
				for(String entry : list_details)
				{
					output = output + delimiter + entry;
				}
			}
			//
			//write string!
			//
			driver.write_manifest_entry(pw, header, output);
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_as_single_line", e);
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
	public boolean write_manifest(PrintWriter pw, String header, String delimiter, boolean include_underline, boolean print_output_as_single_line, boolean printing_vad_node_called_by_process)
	{
		try
		{
			if(pw == null)
				return false;	
			
			delimiter = delimiter + " ";
			
			if(print_output_as_single_line)
				return write_manifest_as_single_line(pw, header, delimiter);
							 			
			driver.write_manifest_entry(pw, header, "plugin_name", plugin_name);
			driver.write_manifest_entry(pw, header, "pid", pid);
			if(PID > -1)	driver.write_manifest_entry(pw, header, "PID", ""+PID);
			driver.write_manifest_entry(pw, header, "process_name", process_name);
			
			//
			//GDI Timers
			//
			driver.write_manifest_entry(pw, header, "session", session);
			driver.write_manifest_entry(pw, header, "handle", handle);
			driver.write_manifest_entry(pw, header, "object", object);
			driver.write_manifest_entry(pw, header, "thread", thread);
			driver.write_manifest_entry(pw, header, "process_details", process_details);
			driver.write_manifest_entry(pw, header, "nID", nID);
			driver.write_manifest_entry(pw, header, "rate_ms", rate_ms);
			driver.write_manifest_entry(pw, header, "countdown_ms", countdown_ms);
			driver.write_manifest_entry(pw, header, "function", function);
			
			//
			//Callbacks
			//	
//public volatile Node_Driver node_driver = null;
			driver.write_manifest_entry(pw, header, "type", type);
			driver.write_manifest_entry(pw, header, "callback", callback);
			driver.write_manifest_entry(pw, header, "module_name", module_name);
			driver.write_manifest_entry(pw, header, "details", details);
			
			//
			//timers
			//
			driver.write_manifest_entry(pw, header, "offset_v", offset_v);
			driver.write_manifest_entry(pw, header, "due_time", due_time);
			driver.write_manifest_entry(pw, header, "period_ms", period_ms);
			driver.write_manifest_entry(pw, header, "signaled", signaled);
			driver.write_manifest_entry(pw, header, "routine", routine);

			//
			//Unloaded Modules
			//
			driver.write_manifest_entry(pw, header, "start_address", start_address);
			driver.write_manifest_entry(pw, header, "end_address", end_address);
			driver.write_manifest_entry(pw, header, "date", date);
			driver.write_manifest_entry(pw, header, "time", time);

			//
			//userassist
			//
			driver.write_manifest_entry(pw, header, "reg_binary", reg_binary);
			driver.write_manifest_entry(pw, header, "raw_data_first_line", raw_data_first_line);
			driver.write_manifest_entry(pw, header, "id", id);
			driver.write_manifest_entry(pw, header, "count", count);
			driver.write_manifest_entry(pw, header, "focus_count", this.focus_count);
			driver.write_manifest_entry(pw, header, "time_focused", this.time_focused);
			driver.write_manifest_entry(pw, header, "last_updated", last_updated);

			//
			//vadinfo
			//
			driver.write_manifest_entry(pw, header, "offset", offset);
			driver.write_manifest_entry(pw, header, "name", name);
			driver.write_manifest_entry(pw, header, "path", path);

			//
			//deskscan
			//
			driver.write_manifest_entry(pw, header, "desktop_offset", desktop_offset);
			driver.write_manifest_entry(pw, header, "next", next);
			driver.write_manifest_entry(pw, header, "session_id", session_id);
			driver.write_manifest_entry(pw, header, "desktop_info", desktop_info);
			driver.write_manifest_entry(pw, header, "size", size);
			driver.write_manifest_entry(pw, header, "fshooks", fshooks);
			driver.write_manifest_entry(pw, header, "spwnd", spwnd);
			driver.write_manifest_entry(pw, header, "windows", windows);
			driver.write_manifest_entry(pw, header, "heap", heap);
			driver.write_manifest_entry(pw, header, "limit", limit);
			driver.write_manifest_entry(pw, header, "base", base);
						
			//
			//impscan
			//			
			driver.write_manifest_entry(pw, header, "impscan_start_address", impscan_start_address);
			driver.write_manifest_entry(pw, header, "impscan_end_address", impscan_end_address);
			driver.write_manifest_entry(pw, header, "IAT", IAT);
			driver.write_manifest_entry(pw, header, "call", call);
//public volatile Node_DLL_Container_Impscan DLL_Container_Impscan);
			driver.write_manifest_entry(pw, header, "function_name_lower", function_name_lower);

			//
			//filescan
			//
			driver.write_manifest_entry(pw, header, "offset_p", offset_p);
			driver.write_manifest_entry(pw, header, "num_ptr", num_ptr);
			driver.write_manifest_entry(pw, header, "num_hnd", num_hnd);
			driver.write_manifest_entry(pw, header, "access", access);
			driver.write_manifest_entry(pw, header, "path_name", path_name);

			//
			//File XREF
			//
			driver.write_manifest_entry(pw, header, "file_name", file_name);

			//
			//DLLDUMP
			//Process(V)         Name                 Module Base        Module Name          Result
			//------------------ -------------------- ------------------ -------------------- ------
			//0xfffffa800148f040 smss.exe             0x0000000047ef0000 smss.exe             OK: module.248.3f68f040.47ef0000.dll);
			//0xfffffa800148f040 smss.exe             0x0000000077c90000 ntdll.dll            OK: module.248.3f68f040.77c90000.dll);
			driver.write_manifest_entry(pw, header, "process_offset_V", process_offset_V);
			driver.write_manifest_entry(pw, header, "module_base_address", module_base_address);
			driver.write_manifest_entry(pw, header, "process_offset_P_trimmed", process_offset_P_trimmed);
			driver.write_manifest_entry(pw, header, "module_base_address_trimmed", module_base_address_trimmed);
			driver.write_manifest_entry(pw, header, "module_basse_address_trimmed", module_basse_address_trimmed);
			

			
			
			
			
			
			
			
			if(this.fle != null)
				driver.write_manifest_entry(pw, header, "fle", "/" + fle.getParentFile().getName() + "/" + fle.getName());


			if(list_details != null && !list_details.isEmpty())
			{
				for(String entry : list_details)
				{
					driver.write_manifest_entry(pw, header, " list_details\t " + entry);
				}
			}

			if(include_underline)
				pw.println(Driver.END_OF_ENTRY_MINOR);
			
			//indicate printed node under process
			this.printed_vad_info_node_under_process = printing_vad_node_called_by_process;

			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest", e);
		}
		
		return false;
	}
	
	
	
	public String get_manifest_impscan(String end_token, String delimiter)
	{
		try
		{
			return 	"IAT" + end_token + "\t " + IAT + delimiter +  
					"call" + end_token + "\t "+ call + delimiter +
					"function" + end_token + "\t " + function + delimiter + 
					"function_name_lower" + end_token + "\t " + function_name_lower + delimiter;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_manifest_impscan");
		}
		
		return "";
	}
	
	
	public String get_user_assist_line_for_sortable_array(String delimiter)
	{
		String line = "";
		
		try
		{
			if(this.registry_hive != null)
				line = this.registry_hive.registry + delimiter;
			else if(this.registry_key != null && this.registry_key.registry_hive != null)
				line = registry_key.registry_hive.registry + delimiter;
								
			if(this.registry_key != null && this.registry_key.path != null)
				line = line + this.registry_key.path + delimiter;
			else if(this.registry_hive != null && this.registry_hive.path != null)
				line = line + this.registry_hive.path + delimiter;
			
			line = line + 	this.reg_binary + delimiter + 
							this.time_focused + delimiter + 
							this.last_updated + delimiter + 
							this.count + delimiter + 
							this.focus_count + delimiter + 
							this.raw_data_first_line;									
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_user_assist_line_for_sortable_array", e);
		}
		
		return line;
	}
	
	
	
	
	
	
	
}
