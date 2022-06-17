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
	
	/**populated when import manifest is importing Sessions entries*/
	public volatile LinkedList<String> list_session_entries = null;
	
	public volatile LinkedList<String> list_details = null;
	
	/**used in write_node_information for the graph to know what to label each new node*/
	public volatile String GRAPH_KEY_NAME = null;
	
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
	public volatile int PID = -2;
	
	//
	//indicate if vad_node has been printed under process vad tree  - use this to remove duplication of vad_info being printed by write_manifest
	//
	public volatile boolean printed_vad_info_node_under_process = false;
	
	/**populatd e.g., in import_manifest*/
	public volatile Advanced_Analysis_Director director = null;
	
	/**
	 * indicate key valuye for import_manifest_line_entry
	 */
	public static final int INDEX_KEY_GDI_TIMERS = 0, 
							INDEX_KEY_ENVARS = 1, 
							INDEX_KEY_IMPSCAN = 2, 
							INDEX_KEY_HASHDUMP = 3, 
							INDEX_KEY_HIVELIST = 4, 
							INDEX_KEY_GETSIDS = 5, 
							INDEX_KEY_GET_SERVICE_SID = 6;
	
	
	public volatile String key_name = null;
	public volatile String snapshot_manifest_VALUE_1_same_value = null;
	public volatile String snapshot_manifest_DIFFERENCE_value = null;
	
	/**
	 * Snapshot comparator. If both values are the same, snapshot_value_1 is set, and snapshot_value_2 is null. If there's a difference, snapshot_value_1 holds value 1, and snapthot 2 is set with the value from manifest 2. If snapshot_value_2 is set, then it indicates there was a difference.  If both are null, then the value was never set.
	 * @param key_name
	 * @param snapshot_value_1
	 * @param snapshot_value_2
	 */
	public Node_Generic(String Key_Name, String value_1, String value_2)
	{
		try
		{
			key_name = Key_Name; 
			
			//normalize null values
			if(value_1 != null && (value_1.trim().equals("") || value_1.trim().equalsIgnoreCase("null")))
				value_1 = null;
			if(value_2 != null && (value_2.trim().equals("") || value_2.trim().equalsIgnoreCase("null")))
				value_2 = null;
			
			
			//perform the compare operations
			if(value_1 == null && value_2 != null)
			{
				snapshot_manifest_VALUE_1_same_value = "NOT FOUND";
				snapshot_manifest_DIFFERENCE_value = value_2;
			}
			
			else if(value_2 == null && value_1 != null)
			{
				snapshot_manifest_VALUE_1_same_value = value_1;
				snapshot_manifest_DIFFERENCE_value = "NOT FOUND";
			}
			
			else if(value_1.toLowerCase().trim().equals(value_2.toLowerCase().trim()))
				snapshot_manifest_VALUE_1_same_value = value_1;
			
			else//there is a difference
			{
				snapshot_manifest_VALUE_1_same_value = value_1;
				snapshot_manifest_DIFFERENCE_value = value_2;
			}
						
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Comparator constructor", e);
		}
	}
	
	/**
	 * returns 1 iff stating there was a difference from snapshots!
	 * @param pw
	 * @param jta
	 * @return
	 */
	public int write_snapshot_report(PrintWriter pw, JTextArea_Solomon jta)
	{
		try
		{
			//check if there was a difference
			if(snapshot_manifest_DIFFERENCE_value != null)
			{
				jta.append(this.key_name.toUpperCase());
				jta.append("\t Snapshot Manifest 1 value: " + snapshot_manifest_VALUE_1_same_value);
				jta.append("\t Snapshot Manifest 2 value: " + snapshot_manifest_DIFFERENCE_value);
				return 1;
			}
			
				
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_snapshot_report", e);
		}
		
		return 0;
	}
	
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
			if(this.GRAPH_KEY_NAME == null)
				this.GRAPH_KEY_NAME = "Entry";
			
			pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html(GRAPH_KEY_NAME).replace("\\", "\\\\") + "\" , \"children\": [");
			
			//driver.write_node_ENTRY("SID: ", this.sid, pw);
			
			if(PID > -2)
				driver.write_node_ENTRY("PID: ", ""+this.PID, pw);
			
			driver.write_node_ENTRY("pid: ", this.pid, pw);
			driver.write_node_ENTRY("Process Name: ", this.process_name, pw);
			driver.write_node_ENTRY("Session: ", this.session, pw);
			driver.write_node_ENTRY("Handle: ", this.handle, pw);
			driver.write_node_ENTRY("Object: ", this.object, pw);
			driver.write_node_ENTRY("Thread: ", this.thread, pw);
			driver.write_node_ENTRY("Process Details: ", this.process_details, pw);
			driver.write_node_ENTRY("nID: ", this.nID, pw);
			driver.write_node_ENTRY("Rate (ms): ", this.rate_ms, pw);
			driver.write_node_ENTRY("Countdown (ms): ", this.countdown_ms, pw);
			driver.write_node_ENTRY("Function: ", this.function, pw);
			driver.write_node_ENTRY("Type: ", this.type, pw);
			driver.write_node_ENTRY("Callback: ", this.callback, pw);
			driver.write_node_ENTRY("Module Name: ", this.module_name, pw);
			driver.write_node_ENTRY("Details: ", this.details, pw);
			driver.write_node_ENTRY("Offset V: ", this.offset_v, pw);
			driver.write_node_ENTRY("Due Time: ", this.due_time, pw);
			driver.write_node_ENTRY("Period Ms: ", this.period_ms, pw);
			driver.write_node_ENTRY("Signaled: ", this.signaled, pw);
			driver.write_node_ENTRY("Routine: ", this.routine, pw);
			driver.write_node_ENTRY("Start Address: ", this.start_address, pw);
			driver.write_node_ENTRY("End Address: ", this.end_address, pw);
			driver.write_node_ENTRY("Date: ", this.date, pw);
			driver.write_node_ENTRY("Time: ", this.time, pw);
			driver.write_node_ENTRY("Reg Binary: ", this.reg_binary, pw);
			driver.write_node_ENTRY("Raw Data First Line: ", this.raw_data_first_line, pw);
			driver.write_node_ENTRY("ID: ", this.id, pw);
			driver.write_node_ENTRY("Count: ", this.count, pw);
			driver.write_node_ENTRY("Focus Count: ", this.focus_count, pw);
			driver.write_node_ENTRY("Time Focused: ", this.time_focused, pw);
			driver.write_node_ENTRY("Last Updated: ", this.last_updated, pw);
			driver.write_node_ENTRY("Offset: ", this.offset, pw);
			driver.write_node_ENTRY("Name: ", this.name, pw);
			driver.write_node_ENTRY("Path: ", this.path, pw);
			driver.write_node_ENTRY("Desktop Offset: ", this.desktop_offset, pw);
			driver.write_node_ENTRY("Next: ", this.next, pw);
			driver.write_node_ENTRY("Session ID: ", this.session_id, pw);
			driver.write_node_ENTRY("Desktop Info: ", this.desktop_info, pw);
			driver.write_node_ENTRY("Size: ", this.size, pw);
			driver.write_node_ENTRY("Fshooks: ", this.fshooks, pw);
			driver.write_node_ENTRY("Spwnd: ", this.spwnd, pw);
			driver.write_node_ENTRY("Windows: ", this.windows, pw);
			driver.write_node_ENTRY("Heap: ", this.heap, pw);
			driver.write_node_ENTRY("Limit: ", this.limit, pw);
			driver.write_node_ENTRY("Base: ", this.base, pw);
			driver.write_node_ENTRY("Impscan Start Address: ", this.impscan_start_address, pw);
			driver.write_node_ENTRY("Impscan End Address: ", this.impscan_end_address, pw);
			driver.write_node_ENTRY("IAT: ", this.IAT, pw);
			driver.write_node_ENTRY("Call: ", this.call, pw);
			driver.write_node_ENTRY("Function Name Lower: ", this.function_name_lower, pw);
			driver.write_node_ENTRY("Offset (P): ", this.offset_p, pw);
			driver.write_node_ENTRY("Num Ptr: ", this.num_ptr, pw);
			driver.write_node_ENTRY("Num Hnd: ", this.num_hnd, pw);
			driver.write_node_ENTRY("Access: ", this.access, pw);
			driver.write_node_ENTRY("Path Name: ", this.path_name, pw);
			driver.write_node_ENTRY("File Name: ", this.file_name, pw);
			driver.write_node_ENTRY("Process Offset (V): ", this.process_offset_V, pw);
			driver.write_node_ENTRY("Module Base Address: ", this.module_base_address, pw);
			driver.write_node_ENTRY("Process Offset P Trimmed: ", this.process_offset_P_trimmed, pw);
			driver.write_node_ENTRY("Module Base Address Trimmed: ", this.module_base_address_trimmed, pw);
			driver.write_node_ENTRY("Module Basse Address Trimmed: ", this.module_basse_address_trimmed, pw);

			this.write_node_information_list("Details", list_details, pw);
			this.write_node_information_list("Session Entries", list_session_entries, pw);
			
			
			pw.println("\t\t" +  "]},");//end process information			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_information", e);
		}
		
		return false;
	}
	
	
	public boolean write_node_information_list(String title, LinkedList<String> list, PrintWriter pw)
	{
		try
		{
			if(list == null || list.isEmpty())
				return false;
			
			pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html(title).replace("\\", "\\\\") + "\" , \"children\": [");
						
			for(String entry : list)
			{
				driver.write_node_ENTRY("", entry, pw);	
			}						
			
			pw.println("\t\t" +  "]},");	
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_information_list", e);
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
	
	public String write_manifest_as_single_line(PrintWriter pw, String header, String delimiter)
	{
		String output = "";
		
		try
		{
			//if(pw == null)
			//	return null;	
									
			output = output + driver.get_trimmed_entry("pid", pid, delimiter, true, false, ":");
			if(PID > -2)	output = output + driver.get_trimmed_entry("PID", ""+PID, delimiter, true, false, ":");
			
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
			if(pw != null)
				driver.write_manifest_entry(pw, header, output);
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_as_single_line", e);
		}
		
		return output;
	}
	
	/**
	 * continuation mtd
	 * @param pw
	 * @param key
	 * @param value
	 * @return
	 */
	public String write_manifest(PrintWriter pw, String header, String delimiter, boolean include_underline, boolean print_output_as_single_line, boolean printing_vad_node_called_by_process)
	{
		try
		{
			if(pw == null)
				return null;	
			
			delimiter = delimiter + " ";
			
			if(print_output_as_single_line)
				return write_manifest_as_single_line(pw, header, delimiter);
							 			
			driver.write_manifest_entry(pw, header, "plugin_name", plugin_name);
			driver.write_manifest_entry(pw, header, "pid", pid);
			if(PID > -2)	driver.write_manifest_entry(pw, header, "PID", ""+PID);
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

			return "";
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest", e);
		}
		
		return null;
	}
	
	/**
	 * process key,value tuple e.g. pid: 	 320, or	 process_name: 	 csrss.exe
	 * @param line_entry
	 * @param arr
	 * @param key
	 * @param value
	 * @param DIRECTOR
	 * @return
	 */
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
			//PROCESS
			//
			if(key.equals("plugin_name")) plugin_name = value;
			else if(key.equals("process_name")) process_name = value;
			else if(key.equals("pid"))
			{
				pid = value;
				
				if(pid == null || pid.toLowerCase().trim().equals("null"))
					pid = "-1";
				
			}
			
			else if(key.equals("PID"))
			{
				try
				{
					PID = Integer.parseInt(value);
				}
				catch(Exception e)
				{
					//catch the exception below if this fails
					try	
					{
						PID = Integer.parseInt(pid);
					}
					catch(Exception ee)
					{
						PID = -1;
						pid = "-1";
					}
				}
				
				try
				{
					if(director != null)
					{
						this.process = director.tree_PROCESS.get(PID);
						
						if(process == null)
							process = director.NULL_PROCESS;
					}
				}
				catch(Exception e)
				{
					if(director != null)
						process = director.NULL_PROCESS;
				}
			}
			
			//
			//GDI Timers
			//
			else if(key.equals("session")) session = value;
			else if(key.equals("handle")) handle = value;
			else if(key.equals("object")) object = value;
			else if(key.equals("thread")) thread = value;
			else if(key.equals("process_details")) process_details = value;
			else if(key.equals("nID")) nID = value;
			else if(key.equals("nid")) nID = value;
			else if(key.equals("rate_ms")) rate_ms = value;
			else if(key.equals("countdown_ms")) countdown_ms = value;
			else if(key.equals("function")) function = value;

			//
			//Callbacks
			//	
			//public volatile Node_Driver node_driver = null;
			else if(key.equals("type")) type = value;
			else if(key.equals("callback")) callback = value;
			else if(key.equals("module_name")) module_name = value;
			else if(key.equals("details")) details = value;

			//
			//timers
			//
			else if(key.equals("offset_v")) offset_v = value;
			else if(key.equals("due_time")) due_time = value;
			else if(key.equals("period_ms")) period_ms = value;
			else if(key.equals("signaled")) signaled = value;
			else if(key.equals("routine")) routine = value;

			//
			//Unloaded Modules
			//
			else if(key.equals("start_address")) start_address = value;
			else if(key.equals("end_address")) end_address = value;
			else if(key.equals("date")) date = value;
			else if(key.equals("time")) time = value;

			//
			//userassist
			//
			else if(key.equals("reg_binary")) reg_binary = value;
			else if(key.equals("raw_data_first_line")) raw_data_first_line = value;
			else if(key.equals("id")) id = value;
			else if(key.equals("count")) count = value;
			else if(key.equals("focus_count")) this.focus_count = value;
			else if(key.equals("time_focused")) this.time_focused = value;
			else if(key.equals("last_updated")) last_updated = value;

			//
			//vadinfo
			//
			else if(key.equals("offset")) offset = value;
			else if(key.equals("name")) name = value;
			else if(key.equals("path")) path = value;

			//
			//deskscan
			//
			else if(key.equals("desktop_offset"))
			{
				desktop_offset = value;
				
				if(director != null)
				{
					director.tree_DESKSCAN.put(desktop_offset, this);
				}
				
			}						
			
			else if(key.equals("next")) next = value;
			else if(key.equals("session_id")) session_id = value;
			else if(key.equals("desktop_info")) desktop_info = value;
			else if(key.equals("size")) size = value;
			else if(key.equals("fshooks")) fshooks = value;
			else if(key.equals("spwnd")) spwnd = value;
			else if(key.equals("windows")) windows = value;
			else if(key.equals("heap")) heap = value;
			else if(key.equals("limit")) limit = value;
			else if(key.equals("base")) base = value; 
			else if(key.equals("process"))	import_process(line_entry);
						
			//
			//impscan
			//
			else if(key.equals("impscan_start_address")) impscan_start_address = value;
			else if(key.equals("impscan_end_address")) impscan_end_address = value;
			else if(key.equals("IAT")) IAT = value;
			else if(key.equals("call")) call = value;
			//public volatile Node_DLL_Container_Impscan DLL_Container_Impscan = value;
			else if(key.equals("function_name_lower")) function_name_lower = value;

			//
			//filescan
			//
			else if(key.equals("offset_p")) offset_p = value;
			else if(key.equals("num_ptr")) num_ptr = value;
			else if(key.equals("num_hnd")) num_hnd = value;
			else if(key.equals("access")) access = value;
			else if(key.equals("path_name")) path_name = value;

			//
			//File XREF
			//
			else if(key.equals("file_name")) file_name = value;

			//
			//DLLDUMP
			//Process(V)         Name                 Module Base        Module Name          Result
			//------------------ -------------------- ------------------ -------------------- ------
			//0xfffffa800148f040 smss.exe             0x0000000047ef0000 smss.exe             OK: module.248.3f68f040.47ef0000.dll = value;
			//0xfffffa800148f040 smss.exe             0x0000000077c90000 ntdll.dll            OK: module.248.3f68f040.77c90000.dll = value;
			else if(key.equals("process_offset_V")) process_offset_V = value;
			else if(key.equals("module_base_address")) module_base_address = value;
			else if(key.equals("process_offset_P_trimmed")) process_offset_P_trimmed = value;
			else if(key.equals("module_base_address_trimmed")) module_base_address_trimmed = value;
			else if(key.equals("module_basse_address_trimmed")) module_basse_address_trimmed = value;

			
			//
			//list details
			//
			else if(key.startsWith("list_details"))
			{
				if(this.list_details == null)
					this.list_details = new LinkedList<String>();
				
				//trim the line_entry
				line_entry = line_entry.substring(line_entry.indexOf("list_details") + "list_details".length()).trim();
				
				if(!list_details.contains(line_entry))
					list_details.add(line_entry);
			}


			//
			//sessions
			//
			else if(key.startsWith("session_container"))
			{
				this.list_session_entries = new LinkedList<String>();
				
				if(director != null && director.tree_session_entries == null)
					director.tree_session_entries = new TreeMap<String, LinkedList<String>>();
				
				line_entry = line_entry.substring("session_container".length()).trim();
				
				//add first line header
				//list_session_entries.add(line_entry);
				
				//link by line header
				director.tree_session_entries.put(line_entry, list_session_entries);
			}
			
			else if(key.startsWith("session_entry") && list_session_entries != null)
			{
				line_entry = line_entry.substring("session_entry".length()).trim();
				
				if(!list_session_entries.contains(line_entry))
					list_session_entries.add(line_entry);
			}
			
			
			else
				driver.directive("Unknown import_manifest_line_entry key: [" + key + "] value: [" + value + "] recieved in " + this.myClassName + " on line_entry --> " + line_entry);
			
			return true;
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "import_manifest_line_entry", e);
			driver.directive("* * Unknown import_manifest_line_entry key: [" + key + "] value: [" + value + "] recieved in " + this.myClassName + " on line_entry --> " + line_entry);
		}
		
		return false;
	}
	
	/**
	 * process line e.g., deskscan entry --> process	 PID:	 2760	 thread_list:	 2488, 2712
	 * @param line_entry
	 * @return
	 */
	public boolean import_process(String line_entry)
	{
		try
		{
			if(line_entry == null)
				return false;
			
			line_entry = line_entry.trim();
			
			if(line_entry.toLowerCase().startsWith("process"))
				line_entry = line_entry.substring("process".length()).trim();
			
			//bifurcate key and values
			String []arr = line_entry.split("\t");
			
			if(arr == null)
				return false;
			
			String key = "", value = "", thread_list = "";
			int PID = -2;
			for(int i = 0; i < arr.length; i+=2)
			{
				try
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					if(key.startsWith("pid"))
						PID = Integer.parseInt(value);
					
					else if(key.startsWith("thread_list"))
						thread_list = value;
				}
				
				catch(Exception e)
				{
					continue;
				}				
			}
			
			TreeMap<String, Node_Generic> tree = null;
			
			//process PID
			if(PID > -2 && director != null)
			{
				this.process = director.tree_PROCESS.get(PID);
				this.process_name = this.process.process_name;
				
				this.process = director.tree_PROCESS.get(PID);
				this.process_name = this.process.process_name;
				
				//store the process
				if(this.tree_process == null)
					this.tree_process = new TreeMap<Integer, Node_Process>();
				
				this.tree_process.put(PID, process);
				
				//store entry in process
				if(process.tree_deskscan == null)
					process.tree_deskscan = new TreeMap<String, TreeMap<String, Node_Generic>>();
											
				if(process.tree_deskscan.containsKey(this.desktop_offset))
					tree = process.tree_deskscan.get(this.desktop_offset);
				
				if(tree == null)
				{
					tree = new TreeMap<String, Node_Generic>();
					process.tree_deskscan.put(this.desktop_offset, tree);
				}								
			}
			
			//process thread_list
			if(thread_list != null && thread_list.trim().length() > 0 && tree != null)
			{
				String list [] = thread_list.split(",");
				
				if(list == null || list.length < 1)
					list = new String[]{thread_list};
				
				for(String thread_id : list)
				{
					tree.put(thread_id, this);
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_process", e);
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
				line = this.registry_hive.registry_hive + delimiter;
			else if(this.registry_key != null && this.registry_key.registry_hive != null)
				line = registry_key.registry_hive.registry_hive + delimiter;
								
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
	
	
	/**
	 * import single line entries e.g. 
	 * @param mtd_designator
	 * @param line
	 * @param director
	 * @param process
	 * @param tree_process
	 * @param tree_director
	 * @return
	 */
	public static boolean import_manifest_line_entry_NODE_IS_ENTIRE_LINE(String mtd_designator, String line, Advanced_Analysis_Director director, Node_Process process, int index_key)
	{
		try
		{
			if(line == null)
				return false;
			
			if(mtd_designator != null && line.toLowerCase().trim().startsWith(mtd_designator.toLowerCase().trim()))
				line = driver.trim_key(mtd_designator, line, true);					
			
			String arr [] = line.split("\t");
			
			//validate entries
			if(arr == null || arr.length < 2)
			{
				driver.directive("* * * invalid import_manifest_line_entry mtd_designator: [" + mtd_designator + "] recieved in " + myClassName + "\t line --> " + line);
				return false;
			}
			
			//validate key, value tuple(s)
			if(arr.length%2 != 0)
			{
				driver.directive("* * * incongruent import_manifest_line_entry mtd_designator: [" + mtd_designator + "] recieved in " + myClassName + "\t line --> " + line);
				return false;
			}
			
			/////////////////////////////////////////////////////////////////////////
			// instantiate node
			/////////////////////////////////////////////////////////////////////////
			Node_Generic node = new Node_Generic(mtd_designator);
			
			
			//
			//set container structure to node
			//
			if(process == null)
				process = director.NULL_PROCESS;
			
			node.process = process;
			node.PID = process.PID;

			//remove if superfluous
			node.pid = "" + process.PID;				
			
			
			//init
			String key = "", value = "";
			
			//
			//process entry
			//
			for(int i = 0; i < arr.length; i+=2)
			{
				try
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					if(key.endsWith(":"))
						key = key.substring(0, key.length()-1).trim();

					/////////////////////////////////////////////////////////////////////////
					// set PID
					/////////////////////////////////////////////////////////////////////////
					if(key.equals("pid"))
					{
						//node.pid = value;						
						
						if((process == null || process == director.NULL_PROCESS) && director != null)
						{
							try	
							{	
								node.PID = Integer.parseInt(value);
								node.process = director.tree_PROCESS.get(node.PID);
							}
							catch(Exception e)
							{
								driver.directive("\nNOTE: I could not set PID in import_manifest_line_entry mtd in " + myClassName + " from key [" + key + "] \t value: [" + value + "] on line --> " + line);
								
								process = director.NULL_PROCESS;
							}
						}
					}
					
					/////////////////////////////////////////////////////////////////////////
					// set values
					/////////////////////////////////////////////////////////////////////////
					else
						node.import_manifest_line_entry(line, arr, key, value, director);
					
					
//					else
//						driver.directive("Unknown import_manifest_line_entry in class: " + myClassName + " at index: [" + i + "] key:[" + key + "] value:[" + value + "] on line --> "  + line);
				}
				catch(Exception e)
				{
					driver.directive("Exception in import_manifest_line_entry in class: " + myClassName + " at index: [" + i + "] key:[" + key + "] value:[" + value + "] on line --> "  + line);
					continue;
				}
			}
			
			/////////////////////////////////////////////////////////////////////////
			// Store values!
			/////////////////////////////////////////////////////////////////////////
			switch(index_key)
			{
				case INDEX_KEY_GDI_TIMERS:
				{
					if(process.tree_gdi_timers == null)
						process.tree_gdi_timers = new TreeMap<String, Node_Generic>();
						
					//
					//store in process tree
					//
					process.tree_gdi_timers.put(node.object, node);
					
					//
					//store in director tree
					//
					director.tree_GDI_TIMERS.put(process.PID,  process);
					break;
				}				
				
				default:
				{
					driver.directive("index_key error! import_manifest_line_entry in class: " + myClassName + ". I can not determine based on index_key which key to use as the key to store in Node_Generic tree. Supplied key:[" + key + "] value:[" + value + "] on line --> "  + line);
				}
			}
					
				
			
			
			
			
			
			
			
		}
		catch(Exception e)
		{
			driver.directive("* * Unknown import_manifest_line_entry key: [" + mtd_designator + "] recieved in " + myClassName + "\t line --> " + line);
		}
		
		return false;
	}
	
	
	
	
	
	public String get_snapshot_analysis_key_VAD()// throws NullPointerException
	{
		try
		{
			return this.offset;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_snapshot_analysis_key_VAD", e);
		}
		
		return this.offset;
	}
	
	public String get_snapshot_analysis_key_DESKSCAN()// throws NullPointerException
	{
		try
		{
			return this.offset;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_snapshot_analysis_key_DESKSCAN", e);
		}
		
		return this.offset;
	}
	
	public String get_snapshot_analysis_COMPARATOR_VALUE()// throws NullPointerException
	{
		try
		{
			return 	this.write_manifest_as_single_line(null, "", "\t");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_snapshot_analysis_COMPARATOR_VALUE", e);
		}
		
		return "==++++++==";
	}
	
	
	
	public String get_snapshot_analysis_COMPARATOR_VALUE_IMPSCAN()// throws NullPointerException
	{
		String output = "";
		
		try
		{
			output = output + driver.get_trimmed_entry("function", function, "\t", true, false, ":");
			output = output + driver.get_trimmed_entry("impscan_start_address", impscan_start_address, "\t", true, false, ":");
			output = output + driver.get_trimmed_entry("impscan_end_address", impscan_end_address, "\t", true, false, ":");
			output = output + driver.get_trimmed_entry("IAT entry address", IAT, "\t", true, false, ":");
			output = output + driver.get_trimmed_entry("call", call, "\t", true, false, ":");			
			output = output.trim();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_snapshot_analysis_COMPARATOR_VALUE", e);
		}
		
		return output;
	}
	
	
	
	
	
	public String get_comparator_key()// throws NullPointerException
	{
		
		
		try
		{
			if(function != null && function.trim().length() > 1)
				return "function: " + function;
			else if(IAT != null && IAT.trim().length() > 1)
				return "IAT entry address: " + IAT;
			else if(call != null && call.trim().length() > 1)
				return "call address: " + call;
			else if(call != null && call.trim().length() > 1)
				return "call address: " + call;
			else if(impscan_start_address != null && impscan_start_address.trim().length() > 1)
				return "impscan_start_address: " + impscan_start_address;
			else if(impscan_end_address != null && impscan_end_address.trim().length() > 1)
				return "impscan_end_address: " + impscan_end_address;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_snapshot_analysis_COMPARATOR_VALUE", e);
		}
		
		return null;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
