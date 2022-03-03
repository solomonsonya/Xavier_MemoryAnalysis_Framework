/**
 * Create the Tree of Processes
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;

import Advanced_Analysis.Analysis_Plugin.Analysis_Plugin_dlllist;
import Advanced_Analysis.Analysis_Plugin.Analysis_Plugin_impscan;
import Advanced_Analysis.Analysis_Report.*;

public class Node_Process
{
	public static final String myClassName = "Node_Process";
	public static volatile Driver driver = new Driver();
	public static final boolean PROCESS_IMPSCAN_IN_SEPARATE_THREAD = true;
	
	
	public volatile Advanced_Analysis_Director director = null;
	
	public volatile String lower = null;
	
	public volatile String XREF_FOUND_TOKENS = "";
	public volatile String XREF_SEARCH_STRING = "";
	public volatile String XREF_SEARCH_STRING_LOWER = "";
	public volatile boolean XREF_SEARCH_HIT_FOUND = false;
	public volatile boolean I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = false;
	
	public static final int MAX_TREE_NODE_COUNT = Advanced_Analysis_Director.MAX_TREE_NODE_COUNT;
	
	public volatile TreeMap<Integer, Node_Process> tree_child_process = null;
	
	/**linked by DLL path*/
	public volatile TreeMap<String, Node_DLL> tree_dll = new TreeMap<String, Node_DLL>();
	
	/**linked by DLL VAD_base_start address*/
	public volatile TreeMap<String, Node_DLL> tree_dll_VAD_base_start_address = new TreeMap<String, Node_DLL>();
	
	public volatile TreeMap<String, Node_Netstat_Entry> tree_netstat = new TreeMap<String, Node_Netstat_Entry>();
	
	public volatile TreeMap<String, Node_Handle> tree_handles = new TreeMap<String, Node_Handle>();		
		public volatile TreeMap<String, Node_Handle> tree_handles_Process = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_Thread = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_Key = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_Event = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_File = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_Directory = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_Desktop = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_Port = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_KeyedEvent = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_SymbolicLink = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_Section = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_WindowStation = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_Mutant = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_Semaphore = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_Timer = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_WaitablePort = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_Job = new TreeMap<String, Node_Handle>();
		public volatile TreeMap<String, Node_Handle> tree_handles_GENERIC = new TreeMap<String, Node_Handle>();
		
		public volatile TreeMap<String, Node_Privs>  tree_privs = null;
		public volatile TreeMap<String, Node_svcscan> tree_services_svcscan = null;
		public volatile TreeMap<String, String> tree_sids = null;
		public volatile TreeMap<String, Node_Malfind> tree_malfind = null;
		public volatile TreeMap<String, Node_Threads> tree_threads = null;
		/**object is the unique key e.g.   0      0x13004f (object) 0xe1592bd8      644 csrss.exe:608            0x7ffd      35000         35000 0xbf8f4d5f*/
		public volatile TreeMap<String, Node_Generic> tree_gdi_timers = null;
		public volatile TreeMap<String, Node_ApiHook> tree_api_hook = new TreeMap<String, Node_ApiHook>();
		public volatile TreeMap<String, Node_Generic> tree_vad_info = null;
		public volatile TreeMap<String, TreeMap<String, Node_Generic>> tree_deskscan = null;
		public volatile TreeMap<String, Node_DLL_Container_Impscan> tree_impscan_DLL_containers = new TreeMap<String, Node_DLL_Container_Impscan>();
		
		//to create tree object of nodes linked by PAGE_READWRITE, PAGE_EXECUTE_WRITECOPY, etc 
		public volatile TreeMap<String, LinkedList<Node_Generic>> tree_vad_page_protection = new TreeMap<String, LinkedList<Node_Generic>>();
		
		/**populated by Node_CmdScan*/
		public volatile LinkedList<Node_CmdScan> list_cmd_scan = null;
		
		public volatile TreeMap<String, Node_CmdScan> tree_cmdscan_consoles = null;
	
		/**from vadinfo, if the VAD entry contains name: to this process, then we have the specific node to this process...*/
		public volatile Node_Generic VAD = null;

		public volatile Analysis_Plugin_impscan impscan = null;
		
	public volatile TreeMap<String, Node_Envar> tree_environment_vars = new TreeMap<String, Node_Envar>();
			
	//Set in analyzeplugin dump class
	public volatile File fle = null;
	public volatile FileAttributeData fle_attributes = null;
	public volatile String file_name = null;
	public volatile String extension = "";
	
	public volatile Node_Process parent_process = null;
	
	public volatile String process_name = "";
	public volatile int PID = -1;
	public volatile int PPID = -1;
	
	public volatile String command_line = "";
	
	//
	//pslist
	//
	public volatile String threads  = "";
	public volatile String handles = "";
	public volatile String wow64 = "";	
	public volatile String session = "";	
	public volatile String offset_pslist = "";
	
	//
	//psscan
	//
	public volatile String PDB = "";	
	public volatile String time_created_date = "";
	public volatile String time_created_time = "";
	public volatile String time_created_UTC = "";
	public volatile String time_exited_date = "";
	public volatile String time_exited_time = "";
	public volatile String time_exited_UTC = "";	
	public volatile String offset_psscan = "";
	
	//
	//pstree
	//
	public volatile String offset_pstree = "";
	
	//
	//psxview
	//
	public volatile String offset_psxview = "";
	public volatile String psxview_pslist = "";
	public volatile String psxview_psscan = "";
	public volatile String psxview_thrdproc = "";
	public volatile String psxview_pspcid = "";
	public volatile String psxview_csrss = "";
	public volatile String psxview_session = "";
	public volatile String psxview_deskthrd = "";
	
	//
	//dlldump
	//
	public volatile String offset_V_dlldump = null;
	public volatile String offset_P_dlldump_trimmed = null;
	public volatile String module_base_address_dlldump = null;
	public volatile String module_base_address_dlldump_trimmed = null;
	
	//
	//dlllist
	//
	/**launch path e.g. C:\Documents and Settings\Adham\Desktop\payload3.exe	*/
	public volatile String path = null;
	public volatile Node_DLL my_module_description = null;
	
	/**holds DLL that has at least 1 function imported into the process. Search the DLL's import tree to find the specific function that links to this process - populated by dependencies*/
	public volatile TreeMap<String, Node_DLL> tree_import_functions_DEPRECATED = new TreeMap<String, Node_DLL>();
	
	//
	//cmdscan show console
	//
	public volatile boolean alert_user_regarding_presence_of_console = false;
	
	
	//
	//
	//
	public volatile boolean found_in_pslist = false;
	public volatile boolean found_in_psscan = false;
	
	public volatile File fle_vadtree_output_data = null;
	public volatile File fle_vadtree_output_image = null;
	public volatile String relative_path_vadtree_image = null;
	
	//
	//jtaConsoles
	//
	public volatile JTextArea_Solomon jtaConsolesOutput = null;
	public volatile boolean consoles_has_been_added_to_gui = false;
	
	public Node_Process(Advanced_Analysis_Director DIRECTOR, int pid, String PROCESS_NAME)
	{
		try
		{
			director = DIRECTOR;
			PID = pid; 
			process_name = PROCESS_NAME;						
			
			//scan for own imports
			if(director.PROCESS_IMPSCAN && PID > -1)
				impscan = new Analysis_Plugin_impscan(null, director, "impscan", "Scan for calls to imported functions", Analysis_Plugin_impscan.EXECUTE_VIA_THREAD, Interface.jpnlAdvancedAnalysisConsole, this);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}			
	}
	
	/**
	 * override
	 */
	public String toString()
	{
		try	{	return toString_header("\t");	}
		catch(Exception e)
		{
			return " * * *"; 
		}
	}
	
	public String toString_header(String delimiter)
	{
		try
		{			//
					//pslist
					//
			return 	"process name: " + process_name  + delimiter + 
					"PID: " + PID + delimiter + 
					"PPID: " + PPID + delimiter + 
					"Threads: " + threads   + delimiter + 
					"Handles: " + handles  + delimiter + 
					"Wow64: " + wow64  + delimiter + 
					"Start date: " + this.time_created_date  + delimiter + 
					"Start time: " + this.time_created_time  + delimiter + 
					"Start UTC: " + this.time_created_UTC  + delimiter + 
					"Exit Date: " + this.time_exited_date  + delimiter + 
					"Exit Time: " + this.time_exited_time  + delimiter + 
					"Exit UTC: " + this.time_exited_UTC  + delimiter +					
					"Session: " + session + delimiter + 
					"offset_pslist: " + offset_pslist + delimiter +
			
					//
					//psscan
					//
					"Time Created date: " + time_created_date  + delimiter + 
					"Time Created time: " + time_created_time  + delimiter + 
					"Time Created UTC: " + time_created_UTC  + delimiter + 
					"Time Exited Date: " + time_exited_date  + delimiter + 
					"Time Exited Time: " + time_exited_time  + delimiter + 
					"Time Exited UTC: " + time_exited_UTC  + delimiter +
					"PDB: " + PDB + delimiter +
					"offset_psscan: " + offset_psscan  + delimiter 	
					
					//
					//pstree
					//
					+ "offset_pstree: " + offset_pstree + delimiter
					
					//
					//psxview
					//
					 + "psxview_pslist: " + psxview_pslist + delimiter
					 + "psxview_psscan: " + psxview_psscan + delimiter
					 + "psxview_thrdproc: " + psxview_thrdproc + delimiter
					 + "psxview_pspcid: " + psxview_csrss + delimiter
					 + "psxview_session: " + psxview_session + delimiter
					 + "psxview_deskthrd: " + psxview_deskthrd + delimiter
					 
					 + this.get_module_description() + delimiter
			
			;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		return "- - - ";
	}
	
	
	public String get_module_description()
	{
		try
		{
			if(my_module_description != null)
				return "\t" + path + "\t" + my_module_description.toString();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_module_description", e);
		}
		
		return "";
	}
	
	/**
	 * from dlllist
	 * @param base
	 * @param size
	 * @param load_count
	 * @param path
	 * @return
	 */
	public Node_DLL store_dll(Advanced_Analysis_Director director, String base, String size, String load_count, String path)
	{
		try
		{
			if(path == null)
				return null;
			
			path = path.trim();
			
			if(path.equals(""))
				return null;
			
			try	
			{
				if(path.startsWith("\\??\\"))
					path = path.substring(4).trim();
			}
			catch(Exception e){}
			
			path = path.replace("	", " ").replace("\t", " ").trim();
			
			//normalize path
			if(director.system_drive != null && !path.toUpperCase().startsWith(director.system_drive.toUpperCase()))
			{
				if(path.startsWith("\\"))
					path = director.system_drive + path;
				else
					path = director.system_drive + "\\" + path;
			}			
									
			Node_DLL dll = null;
			
			String dll_key = (path).toLowerCase();
			dll = director.tree_DLL_by_path.get(dll_key);
			
			if(dll == null)
			{
				dll = new Node_DLL(this.director);
				director.tree_DLL_by_path.put(dll_key, dll);
				dll.path = path;				
			}
			
			//link dll to process
			if(!this.tree_dll.containsKey(dll_key))
				this.tree_dll.put(dll_key, dll);
			
			if(!this.tree_dll_VAD_base_start_address.containsKey(base))
				this.tree_dll_VAD_base_start_address.put(base, dll);
			
			//link process to dll
			dll.store_dll_base(base, this, director);			
			
			//store data
			if(dll.size == null || dll.size.trim().equals(""))
				dll.size = size;
			
			if(dll.load_count == null || dll.load_count.trim().equals(""))
				dll.load_count = load_count;			
			
			if(dll.path == null || dll.path.trim().equals(""))
				dll.path = path;
							
			//
			//check if we found the launch path
			//
			if(this.path == null && path.toLowerCase().trim().endsWith(process_name.toLowerCase().trim()))
			{
				this.path = path;
				this.my_module_description = dll; //e.g. should include path e.g. C:\Documents and Settings\Adham\Desktop\payload3.exe				
			}									
			
			return dll;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "store_dll", e);
		}
		
		return null;
	}
	
	
	public String get_netstat_print(String delimiter)
	{
		
		try
		{
			String entry = "";
			
			for(Node_Netstat_Entry netstat : this.tree_netstat.values())
				entry = entry + "\n" + netstat.toString(); 
			
				return entry.trim();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_netstat_print", e);
		}
		
		return ";;;";
	}
	
	public boolean print_handles(PrintStream out)
	{
		try
		{
			if(out == null)
				return false;
			
			if(tree_handles == null || tree_handles.size() < 1)
				return false;
			
			out.println(toString());
			for(Node_Handle handle : tree_handles.values())
			{
				if(handle == null)
					continue;
				
				out.println("\t" + handle.toString());
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_handles", e);
		}
		
		return false;
	}
	
	
	
	public boolean link_child_process(Node_Process child_process)
	{
		try
		{
			if(child_process == null)
				return false;
			
			if(tree_child_process == null)
				tree_child_process = new TreeMap<Integer, Node_Process>();
				
			tree_child_process.put(child_process.PID, child_process);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "link_child_process", e);
		}
		
		return false;
	}
	
	public String get_process_html_header()
	{
		try
		{
			return "[" + this.PID + "] " + this.process_name;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_process_html_header", e);
		}
		
		return "*";
	}
	
	public boolean write_process_information_tree(PrintWriter pw, Dependency_File_Writer_Tree output_html_file, Node_Process process)
	{
		try
		{
			//name node
			pw.println("\t" +  "{ \"name\": \"" + normalize_html(get_process_html_header()).replace("\\", "\\\\") + "\" , \"children\": [");
			
			//
			//NODE - parent process
			//
			write_node_parent_process(pw, false);
			//
			//NODE - process informaiton
			//
			write_node_process_information(pw);
			
			//
			//NODE - File Attributes
			//
			if(this.fle_attributes != null)
				this.fle_attributes.write_node_file_attributes(pw, this, null);
				
			//
			//NODE - netstat
			//
			write_node_netstat(pw, "netstat");			
			
			//
			//NODE - Child Process
			//
			write_node_child_process(pw, output_html_file);
			
			//
			//deskscan
			//
			write_node_deskscan(pw, true, "Deskscan");
			
			//
			//NODE - DLLs
			//
			write_node_dll(pw);			
			
			//
			//NODE - Environment Vars
			//
			write_node_environment_variables(pw);
			
			//
			//NODE - sibling processes
			//
			write_node_sibling_processes(pw);
			
			//
			//NODE- handles
			//
			write_node_handles_director(pw);
			
			//
			//NODE - write cmdscan - command history
			//
			write_node_cmdscan_command_history(pw);
			
			
			//
			//NODE - write privs
			//
			write_node_privs(pw);
			
			
			//
			//NODE - SERVICES
			write_node_service(pw, "Service");
			
			//
			//NODE - SIDS
			//
			write_node_sids(pw);
			
			
			//
			//NODE - MALFIND
			//
			write_node_malfind(pw, true);
			
			//
			//NODE - Threads
			//
			write_node_threads(pw, true, "Threads");
			
			//
			//GDI Timers
			//
			write_node_gdi_timers(pw, true, "GDI Timers");
			
			//
			//my vadinfo
			//
			write_node_my_vad_info(pw, true, "My VAD Info");
			
			//
			//vadinfo
			//
			write_node_vad_info(pw, true, "VAD Info");
			
			
			pw.println("\t" +  "]},");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_process_information_tree", e);
		}
		
		return false;
	}
	
	public boolean write_node_deskscan(PrintWriter pw, boolean include_header_node, String header)
	{
		try
		{
			if(this.tree_deskscan == null)
				return false;
			
			if(include_header_node)
				pw.println("\t\t" +  "{ \"name\": \"" + this.normalize_html(header).replace("\\", "\\\\") + "\" , \"children\": [");
			
			for(String key : this.tree_deskscan.keySet())
			{
				if(key == null || key.trim().equals(""))
					continue;
				
				TreeMap<String, Node_Generic> tree = this.tree_deskscan.get(key);
				
				if(tree == null || tree.isEmpty())
					continue;
				
				//the same generic node is used at every entry for this specific desktop offset address, get one of the generic nodes
				Node_Generic desktop = null;
				
				for(Node_Generic desk : tree.values())
				{
					if(desk != null)
					{
						desktop = desk;
						break;
					}
				}
				
				if(desktop == null)
					continue;
				
				pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html(key).replace("\\", "\\\\") + "\" , \"children\": [");
				
				driver.write_EXPANDED_node_ENTRY("Desktop", desktop.desktop_offset, pw);
				driver.write_EXPANDED_node_ENTRY("Name", desktop.name, pw);
				driver.write_EXPANDED_node_ENTRY("Next", desktop.next, pw);
				driver.write_EXPANDED_node_ENTRY("Session ID", desktop.session_id, pw);
				driver.write_EXPANDED_node_ENTRY("Desktop Info", desktop.desktop_info, pw);
				driver.write_EXPANDED_node_ENTRY("FS Hooks", desktop.fshooks, pw);
				driver.write_EXPANDED_node_ENTRY("spwnd", desktop.spwnd, pw);
				driver.write_EXPANDED_node_ENTRY("Windows", desktop.windows, pw);
				driver.write_EXPANDED_node_ENTRY("Heap", desktop.heap, pw);
				driver.write_EXPANDED_node_ENTRY("Size", desktop.size, pw);
				driver.write_EXPANDED_node_ENTRY("Base", desktop.base, pw);
				driver.write_EXPANDED_node_ENTRY("Limit", desktop.limit, pw);
				
				//write threads
				pw.println("\t\t\t\t" +  "{ \"name\": \"" + this.normalize_html("Threads").replace("\\", "\\\\") + "\" , \"children\": [");
					for(String thread : tree.keySet())
					{
						driver.write_node_ENTRY("", thread, pw);
					}
				pw.println("\t\t\t\t" +  "]},");
					
					
				//end
				pw.println("\t\t\t" +  "]},");
			}
			
			
			if(include_header_node)
				pw.println("\t\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_deskscan", e);
		}
		
		return false;
	}
	
	public boolean write_node_vad_info(PrintWriter pw, boolean include_header_node, String header)
	{
		try
		{
			if(this.tree_vad_info == null)
				return false;
			
			if(include_header_node)
				pw.println("\t\t" +  "{ \"name\": \"" + this.normalize_html(header).replace("\\", "\\\\") + "\" , \"children\": [");
			
			
			if(this.tree_vad_info.size() > MAX_TREE_NODE_COUNT)
			{
				int count = 0;
				pw.println("\t\t\t\t\t" +  "{ \"name\": \"" + this.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
				
					for(Node_Generic vad : this.tree_vad_info.values())
					{
						if(count % MAX_TREE_NODE_COUNT == 0 && count > 0)
						{
							pw.println("\t\t\t" +  "]},");
							
							pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
						}
						
						++count;
						
						if(vad == null)
							continue;
						
						String node_name = vad.offset;
						
						if(vad.name != null && vad.name.trim().length() > 2)
							node_name = vad.name.trim() + " " + vad.offset;
						
						pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html(node_name).replace("\\", "\\\\") + "\" , \"children\": [");
						
						driver.write_EXPANDED_node_ENTRY("Process", this.get_process_html_header(), pw);
						driver.write_EXPANDED_node_ENTRY("Name", vad.name, pw);
						driver.write_EXPANDED_node_ENTRY("Path", vad.path, pw);
						
						if(vad.list_details != null)
						{
							pw.println("\t\t\t\t" +  "{ \"name\": \"" + this.normalize_html("Details").replace("\\", "\\\\") + "\" , \"children\": [");
							
							for(String entry : vad.list_details)
							{						
								driver.write_node_ENTRY("", entry, pw);
							}
							
							pw.println("\t\t\t\t" +  "]},");
						}
						
						pw.println("\t\t\t" +  "]},");
						
					}//end for
				
				pw.println("\t\t\t\t\t" +  "]},");								
			}//end if
			
			else
			{
				for(Node_Generic vad : this.tree_vad_info.values())
				{
					if(vad == null)
						continue;
					
					String node_name = vad.offset;
					
					if(vad.name != null && vad.name.trim().length() > 2)
						node_name = vad.name.trim() + " " + vad.offset;
					
					pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html(node_name).replace("\\", "\\\\") + "\" , \"children\": [");
					
					driver.write_EXPANDED_node_ENTRY("Process", this.get_process_html_header(), pw);
					driver.write_EXPANDED_node_ENTRY("Name", vad.name, pw);
					driver.write_EXPANDED_node_ENTRY("Path", vad.path, pw);
					
					if(vad.list_details != null)
					{
						pw.println("\t\t\t\t" +  "{ \"name\": \"" + this.normalize_html("Details").replace("\\", "\\\\") + "\" , \"children\": [");
						
						for(String entry : vad.list_details)
						{						
							driver.write_node_ENTRY("", entry, pw);
						}
						
						pw.println("\t\t\t\t" +  "]},");
					}												
					pw.println("\t\t\t" +  "]},");
				}
			}
			
			
			
			if(include_header_node)
				pw.println("\t\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_vad_info", e);
		}
		
		return false;
	}
	
	public boolean write_node_my_vad_info(PrintWriter pw, boolean include_header_node, String header)
	{
		try
		{
			if(this.VAD == null)
				return false;
			
			if(include_header_node)
				pw.println("\t\t" +  "{ \"name\": \"" + this.normalize_html(header).replace("\\", "\\\\") + "\" , \"children\": [");
			
			driver.write_EXPANDED_node_ENTRY("Name", VAD.name, pw);
			driver.write_EXPANDED_node_ENTRY("Path", VAD.path, pw);
			driver.write_EXPANDED_node_ENTRY("Offset", VAD.offset, pw);
			
			if(VAD.list_details != null)
			{
				pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html("Details").replace("\\", "\\\\") + "\" , \"children\": [");
				
				for(String entry : VAD.list_details)
				{
					driver.write_node_ENTRY("", entry, pw);
				}
				
				pw.println("\t\t\t" +  "]},");
			}
			
			
			
			if(include_header_node)
				pw.println("\t\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_my_vad_info", e);
		}
		
		return false;
	}
	
	public boolean write_node_gdi_timers(PrintWriter pw, boolean include_header_node, String header)
	{
		try
		{
			if(this.tree_gdi_timers == null)
				return false;
			
			if(include_header_node)
				pw.println("\t\t" +  "{ \"name\": \"" + this.normalize_html(header).replace("\\", "\\\\") + "\" , \"children\": [");
			
			for(Node_Generic node : tree_gdi_timers.values())
			{
				if(node == null)
					continue;
				
				pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html(node.object).replace("\\", "\\\\") + "\" , \"children\": [");
				
				driver.write_node_ENTRY("Session: ", node.session, pw);
				driver.write_node_ENTRY("Handle: ", node.handle, pw);
				driver.write_node_ENTRY("Object: ", node.object, pw);
				driver.write_node_ENTRY("Thread: ", node.thread, pw);
				driver.write_node_ENTRY("Process: ", node.process_details, pw);
				driver.write_node_ENTRY("nID: ", node.nID, pw);
				driver.write_node_ENTRY("Rate (ms): ", node.rate_ms, pw);
				driver.write_node_ENTRY("Countdown (ms): ", node.countdown_ms, pw);
				driver.write_node_ENTRY("Function: ", node.function, pw);
				
				pw.println("\t\t\t" +  "]},");
			}
			
			if(include_header_node)
				pw.println("\t\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_gdi_timers", e);
		}
		
		return false;
	}
	
	public boolean write_node_threads(PrintWriter pw, boolean include_header_node, String header)
	{
		try
		{
			if(this.tree_threads == null)
				return false;
			
			if(include_header_node)
				pw.println("\t\t" +  "{ \"name\": \"" + this.normalize_html(header).replace("\\", "\\\\") + "\" , \"children\": [");
			
			if(tree_threads.size() > MAX_TREE_NODE_COUNT)
			{
				int count = 0;
				
				pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
				
				for(Node_Threads node : tree_threads.values())
				{															
					if(count % MAX_TREE_NODE_COUNT == 0 && count > 0)
					{
						pw.println("\t\t\t" +  "]},");
						
						pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
					}
					
					node.write_node_information(pw);
					
					++count;
				}
				
				pw.println("\t\t\t" +  "]},");								
			}
			
			else
			{
				for(Node_Threads node : tree_threads.values())
				{
					node.write_node_information(pw);
				}
			}
			
			if(include_header_node)
				pw.println("\t\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_threads", e);
		}
		
		return false;
	}
	
	
	public boolean write_node_malfind(PrintWriter pw, boolean include_header_node)
	{
		try
		{
			if(tree_malfind == null)
				return false;
			
			if(include_header_node)
				pw.println("\t\t" +  "{ \"name\": \"" + "MALFIND" + "\" , \"children\": [");
			
			for(Node_Malfind malfind : tree_malfind.values())
			{
				malfind.write_node_information(pw);
			}
			
			if(include_header_node)
				pw.println("\t\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_malfind", e);
		}
		
		return false;
	}
	
	public boolean write_node_sids(PrintWriter pw)
	{
		try
		{
			if(this.tree_sids == null || this.tree_sids.size() < 1)
				return false;
			
			pw.println("\t\t" +  "{ \"name\": \"" + "SIDs" + "\" , \"children\": [");
			
			String value = null;
			
			for(String key : this.tree_sids.keySet())
			{
				value = this.tree_sids.get(key);
				
				if(value == null || value.trim().equals(""))
					continue;
															
				driver.write_node_ENTRY("SID: " + key, "  -- " + value, pw);
			}
			
			pw.println("\t\t" +  "]},");			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_sids", e);
		}
		
		return false;
	}
	
	
//	public boolean write_node_service(PrintWriter pw, String header)
//	{
//		try
//		{
//			if(this.tree_services_svcscan == null || this.tree_services_svcscan.size() < 1)
//				return false;
//			
//			pw.println("\t\t" +  "{ \"name\": \"" + this.normalize_html(header).replace("\\", "\\\\") + "\" , \"children\": [");
//			
//			for(Node_svcscan node : this.tree_services_svcscan.values())
//			{
//				if(node == null)
//					continue;
//								
//				//write priv info
//				node.write_tree_information(pw, null);				
//				
//				
//			}
//			
//			pw.println("\t\t" +  "]},");
//			
//			return true;
//		}
//		catch(Exception e)
//		{
//			driver.eop(myClassName, "write_node_service", e);
//		}
//		
//		return false;
//	}
//	
	
	public boolean write_node_service(PrintWriter pw, String header)
	{
		try
		{
			if(this.tree_services_svcscan == null || this.tree_services_svcscan.size() < 1)
				return false;
			
			pw.println("\t\t" +  "{ \"name\": \"" + this.normalize_html(header).replace("\\", "\\\\") + "\" , \"children\": [");
			
			if(tree_services_svcscan.size() > MAX_TREE_NODE_COUNT)
			{
				int count = 0;						
				pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
				
				for(Node_svcscan node : this.tree_services_svcscan.values())
				{
					if(count % MAX_TREE_NODE_COUNT == 0 && count > 0)
					{
						pw.println("\t\t\t" +  "]},");
						
						pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
					}
					
					if(node == null)
						continue;
							
					//write priv info
					node.write_tree_information(pw, null);		
					
					++count;
				}
				
				pw.println("\t\t\t" +  "]},");								
			}
			
			else
			{
				for(Node_svcscan node : this.tree_services_svcscan.values())
				{
					if(node == null)
						continue;
									
					//write priv info
					node.write_tree_information(pw, null);										
				}
			}
			
			pw.println("\t\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_service", e);
		}
		
		return false;
	}
	
	
	
	public boolean write_node_privs(PrintWriter pw)
	{
		try
		{
			if(this.tree_privs == null || this.tree_privs.size() < 1)
				return false;
			
			pw.println("\t\t" +  "{ \"name\": \"" + "Privs" + "\" , \"children\": [");
			
			for(Node_Privs privs : this.tree_privs.values())
			{
				if(privs == null)
					continue;
				
				pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html(privs.privilege).replace("\\", "\\\\") + "\" , \"children\": [");
				
				//write priv info
				privs.write_tree_entry(pw);
				
				pw.println("\t\t\t" +  "]},");
				
			}
			
			pw.println("\t\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_privs", e);
		}
		
		return false;
	}
	
	
	public boolean write_node_cmdscan_command_history(PrintWriter pw)
	{
		try
		{						
			if(this.list_cmd_scan == null || this.list_cmd_scan.size() < 1)
				return false;
			
			pw.println("\t\t" +  "{ \"name\": \"" + "Command History" + "\" , \"children\": [");
			
			int cmd_history_count = 0;
			for(Node_CmdScan cmd : this.list_cmd_scan)
			{
				if(cmd == null)
					continue;
				
				pw.println("\t\t\t" +  "{ \"name\": \"" + "History[" + cmd_history_count++ + "]" + "\" , \"children\": [");
				
					//header
					pw.println("\t\t\t\t" +  "{ \"name\": \"" + "Command Header" + "\" , \"children\": [");
					
					for(String element : cmd.list_cmd_header)
						this.write_node_ENTRY("", normalize_html(element).replace("\\", "\\\\"), pw);
					
					pw.println("\t\t\t\t" +  "]},");
					
					//commands
					pw.println("\t\t\t\t" +  "{ \"name\": \"" + "Command Details" + "\" , \"children\": [");
					
					for(String element : cmd.list_cmd_details)
						this.write_node_ENTRY("", normalize_html(element).replace("\\", "\\\\"), pw);
					
					pw.println("\t\t\t\t" +  "]},");
					
					//console output
					if(cmd.list_consoles_output != null && cmd.list_consoles_output.size() > 0)
					{
						//consoles
						pw.println("\t\t\t\t" +  "{ \"name\": \"" + "Console Output" + "\" , \"children\": [");
						
						for(String element : cmd.list_consoles_output) 
							this.write_node_ENTRY("", normalize_html(element).replace("\\", "\\\\"), pw);//solo, return here and modify to account for many input lines
						
						pw.println("\t\t\t\t" +  "]},");
					}
					
					
				pw.println("\t\t\t" +  "]},");
				
			}//end for loop
			
			pw.println("\t\t" +  "]},");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_cmdscan_command_history", e);
		}
		
		return false;
	}
	
	
	//
	public boolean write_node_handles_director(PrintWriter pw)
	{
		try
		{
			if(this.tree_handles == null || tree_handles.size() < 1)
				return false;
			
			pw.println("\t\t" +  "{ \"name\": \"" + "Handles" + "\" , \"children\": [");
			
			if(Dependency_File_Writer_Tree.handles_bifurcate_output_into_multiple_subtypes)
			{
				write_node_handles(pw, tree_handles_Process, "Process");
				write_node_handles(pw, tree_handles_File, "File");
				write_node_handles(pw, tree_handles_Key, "Key");
				write_node_handles(pw, tree_handles_Event, "Event");
				write_node_handles(pw, tree_handles_Mutant, "Mutant");
				write_node_handles(pw, tree_handles_Semaphore, "Semaphore");
				write_node_handles(pw, tree_handles_Section, "Section");
				write_node_handles(pw, tree_handles_KeyedEvent, "KeyEvent");
				write_node_handles(pw, tree_handles_Job, "Job");
				write_node_handles(pw, tree_handles_Directory, "Directory");
				write_node_handles(pw, tree_handles_SymbolicLink, "SymbolicLink");
				write_node_handles(pw, tree_handles_Thread, "Thread");											
				write_node_handles(pw, tree_handles_Desktop, "Desktop");
				write_node_handles(pw, tree_handles_Port, "Port");	
				write_node_handles(pw, tree_handles_WaitablePort, "WaitablePort");	
				write_node_handles(pw, tree_handles_WindowStation, "WorkStation");								
				write_node_handles(pw, tree_handles_Timer, "Timer");							
				write_node_handles(pw, tree_handles_GENERIC, "Generic");
				
			}
			else
			{
				write_node_handles(pw, this.tree_handles, null);
			}
			
			pw.println("\t\t" +  "]},");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_handles_director", e);
		}
		
		return false;
	}
	
	public boolean write_node_handles(PrintWriter pw, TreeMap<String, Node_Handle> tree, String header)
	{
		try
		{
			if(tree == null || tree.size() < 1)
				return false;
			
			if(header == null || header.trim().equals(""))
			{
				for(Node_Handle handle : tree.values())
				{
					if(handle == null)
						continue;
					
					pw.println("\t\t\t" +  "{ \"name\": \"" + normalize_html(handle.details).replace("\\", "\\\\") + "\" },");
				}
			}
			else
			{
				pw.println("\t\t" +  "{ \"name\": \"" + this.normalize_html(header).replace("\\", "\\\\") + "\" , \"children\": [");
				
					for(Node_Handle handle : tree.values())
					{
						if(handle == null)
							continue;
						
						pw.println("\t\t\t" +  "{ \"name\": \"" + normalize_html(handle.details).replace("\\", "\\\\") + "\" },");
					}
				
				pw.println("\t\t" +  "]},");
				return true;
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_handles - 2", e);
		}
		
		return false;
	}
	
	/**
	 * All processes instantiated by the same parent
	 * @param pw
	 * @return
	 */
	public boolean write_node_sibling_processes(PrintWriter pw)
	{
		try
		{
			if(this.parent_process == null || this.parent_process.tree_child_process == null || parent_process.tree_child_process.size() < 2)
				return false;
			
			pw.println("\t\t" +  "{ \"name\": \"" + "Sibling Processes" + "\" , \"children\": [");
			
			for(Node_Process process : this.parent_process.tree_child_process.values())
			{
				if(process == null || process == this)
					continue;
				
				pw.println("\t\t\t" +  "{ \"name\": \"" + normalize_html(process.get_process_html_header()).replace("\\", "\\\\") + "\" },");
			}
			
			pw.println("\t\t" +  "]},");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_sibling_process", e);
		}
		
		return false;
	}
	
	public boolean write_node_environment_variables(PrintWriter pw)
	{
		try
		{
			if(tree_environment_vars != null && tree_environment_vars.size() > 0)
			{
				pw.println("\t\t" +  "{ \"name\": \"" + "Environment Variables" + "\" , \"children\": [");
				
					if(tree_environment_vars.size() > MAX_TREE_NODE_COUNT)
					{
						int count = 0;						
						pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
						
						for(Node_Envar variable : tree_environment_vars.values())
						{
							if(count % MAX_TREE_NODE_COUNT == 0 && count > 0)
							{
								pw.println("\t\t\t" +  "]},");
								
								pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
							}
							
							if(variable == null || variable.variable == null || variable.variable.trim().equals("") || variable.value.trim().equals(""))
								continue;
									
							//do work
							pw.println("\t\t\t" +  "{ \"name\": \"" + normalize_html(variable.variable + ":  " + variable.value).replace("\\", "\\\\") + "\" },");
							
							++count;
						}
						
						pw.println("\t\t\t" +  "]},");								
					}
				
					else
					{
						for(Node_Envar variable : tree_environment_vars.values())
						{
							if(variable == null || variable.variable == null || variable.variable.trim().equals("") || variable.value.trim().equals(""))
								continue;
																	
							pw.println("\t\t\t" +  "{ \"name\": \"" + normalize_html(variable.variable + ":  " + variable.value).replace("\\", "\\\\") + "\" },");						
						}
					}
			
				pw.println("\t\t" +  "]},");
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_environment_variables", e);
		}
		
		return false;
	}
	
	public boolean write_node_ENTRY(String title, String value, PrintWriter pw)
	{
		try
		{
			if(value == null || value.trim().equals(""))
				return false;
					
			pw.println("\t\t\t" +  "{ \"name\": \"" + normalize_html(title + " " + value).replace("\\", "\\\\") + "\" },");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_ENTRY", e);
		}
		
		return false;
	}
	
	
	
	public boolean write_node_dll(PrintWriter pw)
	{
		try
		{
			if((tree_dll != null && tree_dll.size() > 0) || (tree_impscan_DLL_containers != null && tree_impscan_DLL_containers.size() > 0))
			{
				pw.println("\t\t" +  "{ \"name\": \"" + "DLLs" + "\" , \"children\": [");
				
				///////////////////////
				//////// Import Files
				/////////////////////
					pw.println("\t\t" +  "{ \"name\": \"" + "Import Files" + "\" , \"children\": [");
				
					if(tree_dll != null && this.tree_dll.size() > MAX_TREE_NODE_COUNT)
					{
						int count = 0;
						
						pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
						
						for(Node_DLL module : this.tree_dll.values())
						{
							if(module == null || module.path == null || module.path.trim().equals(""))
								continue;
							
							//skip some that have already been printed
							if(tree_dll.containsKey("C:"+ module.path) )
								continue;
							
							if(module.path.trim().equals(this.path))
								continue;		
							
							if(count % MAX_TREE_NODE_COUNT == 0 && count > 0)
							{
								pw.println("\t\t\t" +  "]},");
								
								pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
							}
							
							//pw.println("\t\t\t" +  "{ \"name\": \"" + normalize_html(module.path).replace("\\", "\\\\") + "\" },");
							module.write_module_information("\t\t\t", pw, this);
							
							++count;
						}
						
						
						pw.println("\t\t\t" +  "]},");								
					}
					else
					{
						if(tree_dll != null)
						{
							for(Node_DLL module : this.tree_dll.values())
							{
								if(module == null || module.path == null || module.path.trim().equals(""))
									continue;
								
								//skip some that have already been printed
								if(tree_dll.containsKey("C:"+ module.path) )
									continue;
								
								if(module.path.trim().equals(this.path))
									continue;					
								
								//pw.println("\t\t\t" +  "{ \"name\": \"" + normalize_html(module.path).replace("\\", "\\\\") + "\" },");
								module.write_module_information("\t\t\t", pw, this);
							}
						}
					}
						
					//end Import Files Node
					pw.println("\t\t" +  "]},");
					
					
					
					///////////////////////
					//////// Import Functions
					/////////////////////
					
					if(this.tree_impscan_DLL_containers != null && this.tree_impscan_DLL_containers.size() > 0)
					{
						
					
					
						pw.println("\t\t" +  "{ \"name\": \"" + "Import Functions" + "\" , \"children\": [");
					
//below - was working with dependencies import file, however I'll replace with impscan for simplicity and to deprecate dependency on Dependencies file
	/*					
	 					for(Node_DLL module : this.tree_import_functions.values())
						{
							if(module == null || module.path == null || module.path.trim().equals(""))
								continue;
							
							//skip some that have already been printed
							if(tree_dll.containsKey("C:"+ module.path) )
								continue;
							
							if(module.path.trim().equals("") || module.path.trim().equals(this.path))
								continue;		
							
													
							pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html(module.path).replace("\\", "\\\\") + "\" , \"children\": [");
							
							for(Node_Import_DLL_Function function : module.tree_import_function_table_dependencies.values())
							{
								if(function.tree_process.containsKey(this.PID))
									this.write_node_ENTRY("", function.function_name, pw);
							}
							
							pw.println("\t\t\t" +  "]},");						
						}*/
						
						
						if(tree_impscan_DLL_containers != null && tree_impscan_DLL_containers.size() > MAX_TREE_NODE_COUNT)
						{
							int count = 0;				
							pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
							
							for(Node_DLL_Container_Impscan dll_container : this.tree_impscan_DLL_containers.values())
							{															
								if(count % MAX_TREE_NODE_COUNT == 0 && count > 0)
								{
									pw.println("\t\t\t" +  "]},");
									
									pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
								}
								
								dll_container.write_tree_imports(pw);
								
								++count;
							}
							
							pw.println("\t\t\t" +  "]},");								
						}
						
						else
						{
							for(Node_DLL_Container_Impscan dll_container : this.tree_impscan_DLL_containers.values())
							{
								try
								{
									if(dll_container == null || dll_container.module_name == null || dll_container.module_name.trim().equals(""))
										continue;
									
									dll_container.write_tree_imports(pw);
								}
								catch(Exception e)
								{
									continue;
								}
							}
						}
						
						
						
						
						
						pw.println("\t\t" +  "]},");
					}
					
					
				///////////////////////////////////////	
				//end DLL node	
				pw.println("\t\t" +  "]},");
				
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_dll", e);
		}
		
		return false;
	}
	
	public boolean write_node_child_process(PrintWriter pw, Dependency_File_Writer_Tree output_html_file)
	{
		try
		{
			if(this.tree_child_process != null && this.tree_child_process.size() > 0)
			{
				pw.println("\t\t" +  "{ \"name\": \"" + "Child Processes" + "\" , \"children\": [");
				
					for(Node_Process child : this.tree_child_process.values())
					{
						if(child == null)
							continue;
						
						if(child.tree_child_process == null || child.tree_child_process.size() < 1 || !Dependency_File_Writer_Tree.use_recursion_to_produce_process_call_tree)						
							pw.println("\t\t\t" +  "{ \"name\": \"" + normalize_html(child.get_process_html_header()).replace("\\", "\\\\") + "\" },");
						else
						{
							//recurse for the win! @Carpenter1010 -S0lomon Sonya
							pw.println("\t\t" +  "{ \"name\": \"" + normalize_html(child.get_process_html_header()).replace("\\", "\\\\") + "\", \"children\": [");
								output_html_file.write_process_tree_RECURSIVELY(child.tree_child_process, pw, "\t\t\t", this);
							pw.println("\t\t" +  "]},");
						}
					}
				
				pw.println("\t\t" +  "]},");
			}
			
			//print only specific child if necessary
			else if(this.tree_child_process != null && this.tree_child_process.size() == 1)
			{
				for(Node_Process child : this.tree_child_process.values())
				{
					if(child == null)
						continue;
					
					pw.println("\t\t\t" +  "{ \"name\": \"Child Process: " + normalize_html(child.get_process_html_header()) + "\" },");						
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_child_process", e);
		}
		
		return false;
	}
	
	
	public boolean write_node_netstat(PrintWriter pw, String title)
	{
		try
		{
			if(tree_netstat != null && tree_netstat.size() > 0)
			{
				pw.println("\t\t" +  "{ \"name\": \"" + normalize_html(title).replace("\\", "\\\\") + "\" , \"children\": [");
				
				//
				//enter entries with foreign addresses first
				//
				for(Node_Netstat_Entry netstat : tree_netstat.values())
				{
					
					if(netstat.foreign_address == null || netstat.foreign_address.trim().equals(""))
						continue;
					
					String address = netstat.foreign_address;			
					if(address.trim().startsWith("*.*") || address.trim().startsWith("*:*"))
						address = netstat.local_address;
					
					String state = netstat.state;
					
					if(state == null || state.trim().equals(""))
						state = "DETAILS";
										
					if(netstat.list_whois_entry != null && netstat.list_whois_entry.size() > 1)
					{
						pw.println("\t\t\t" +  "{ \"name\": \"" + normalize_html(address).replace("\\", "\\\\") + "\" , \"children\": [");
						
								pw.println("\t\t\t\t" +  "{ \"name\": \"" + normalize_html(state).replace("\\", "\\\\") + "\" , \"children\": [");
									write_node_ENTRY("", netstat.get_html_entry(), pw);
								pw.println("\t\t\t\t" +  "]},");
								
								pw.println("\t\t\t\t" +  "{ \"name\": \"" + normalize_html("Whois").replace("\\", "\\\\") + "\" , \"children\": [");
								
								
									for(String entry : netstat.list_whois_entry)
									{
										entry = normalize_html(entry).replace("\\", "\\\\");
										
										this.write_node_ENTRY("", entry, pw);
									}
								
								pw.println("\t\t\t\t" +  "]},");
						
						pw.println("\t\t\t" +  "]},");
					}
					else //whois is not present
					{																
						pw.println("\t\t\t\t" +  "{ \"name\": \"" + normalize_html(address).replace("\\", "\\\\") + "\" , \"children\": [");
							write_node_ENTRY("", netstat.get_html_entry(), pw);
						pw.println("\t\t\t\t" +  "]},");
					}
				}
				
				//
				//write remaining entries
				//
				for(Node_Netstat_Entry netstat : tree_netstat.values())
				{
					//print the others
					if(netstat.foreign_address != null && !netstat.foreign_address.trim().equals(""))
						continue;
															
					//pw.println("\t\t\t" +  "{ \"name\": \"" + normalize_html(netstat.get_html_entry()).replace("\\", "\\\\") + "\" },");
					
					pw.println("\t\t\t\t" +  "{ \"name\": \"" + normalize_html(netstat.local_address).replace("\\", "\\\\") + "\" , \"children\": [");
						write_node_ENTRY("", netstat.get_html_entry(), pw);
					pw.println("\t\t\t\t" +  "]},");
					
				}
			
				pw.println("\t\t" +  "]},");
				
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_netstat", e);
		}
		
		return false;
	}
	
	
	public boolean write_node_parent_process(PrintWriter pw, boolean include_parent_information)
	{
		try
		{
			if(this.parent_process == null && this.PPID < 0)
				return false;
			
			//
			//Parent Process
			//
			pw.println("\t" +  "{ \"name\": \"Parent Process\" , \"children\": [");
			
				if(this.parent_process != null)
				{
					if(include_parent_information)
					{
						pw.println("\t" +  "{ \"name\": \"" + this.normalize_html(this.parent_process.get_process_html_header()).replace("\\", "\\\\") + "\", \"children\": [");
							this.parent_process.write_node_process_information(pw);
						pw.println("\t\t" +  "]},");//end process information
					}
					else					
						pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html(this.parent_process.get_process_html_header()).replace("\\", "\\\\") + "\" },");
					
				}
				else if(this.PPID > -1)//we have parent pid without active process
					pw.println("\t\t\t" +  "{ \"name\": \"Parent PID: [" + this.PPID + "]\" },");
				
			pw.println("\t\t" +  "]},");//end process information
			
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_parent_process", e);
		}
		
		return false;
	}
	
	public boolean write_node_process_information(PrintWriter pw)
	{
		try
		{
			pw.println("\t" +  "{ \"name\": \"Process Information\" , \"children\": [");
			
				
				//
				//path
				//
				if(path != null && !path.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Path: " + this.normalize_html(path).replace("\\", "\\\\") + "\" },");					
				
				//
				//command_line
				//
				if(command_line != null && !command_line.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Command Line: " + this.normalize_html(command_line).replace("\\", "\\\\") + "\" },");
				
				//
				//time
				//
				if(this.time_created_date != null && !time_created_date.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Creation Time: " + this.normalize_html(this.time_created_date).replace("\\", "\\\\") + " " + this.normalize_html(this.time_created_time).replace("\\", "\\\\") + " " + this.normalize_html(this.time_created_UTC).replace("\\", "\\\\") + "\" },");
				
				if(this.time_exited_date != null && !time_exited_date.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Exited Time: " + this.normalize_html(this.time_exited_date).replace("\\", "\\\\") + " " + this.normalize_html(this.time_exited_time).replace("\\", "\\\\") + " " + this.normalize_html(this.time_exited_UTC).replace("\\", "\\\\") + "\" },");
										
								
				
				//
				//module info
				//
				if(my_module_description != null && my_module_description.file_version != null && !my_module_description.file_version.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"File Version: " + this.normalize_html(my_module_description.file_version).replace("\\", "\\\\") + "\" },");
				
				//
				//product_name
				//
				if(my_module_description != null && my_module_description.product_name != null && !my_module_description.product_name.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Product Name: " + this.normalize_html(my_module_description.product_name).replace("\\", "\\\\") + "\" },");
				
				//
				//original_file_name
				//
				if(my_module_description != null && my_module_description.original_file_name != null && !my_module_description.original_file_name.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Original File Name: " + this.normalize_html(my_module_description.original_file_name).replace("\\", "\\\\") + "\" },");
				
				//
				//os
				//
				if(my_module_description != null && my_module_description.os != null && !my_module_description.os.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"OS: " + this.normalize_html(my_module_description.os).replace("\\", "\\\\") + "\" },");
				
				//
				//comments
				//
				if(my_module_description != null && my_module_description.comments != null && !my_module_description.comments.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Comments: " + this.normalize_html(my_module_description.comments).replace("\\", "\\\\") + "\" },");
				
				//
				//company_name
				//
				if(my_module_description != null && my_module_description.company_name != null && !my_module_description.company_name.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Company Name: " + this.normalize_html(my_module_description.company_name).replace("\\", "\\\\") + "\" },");
				
				//
				//flags
				//
				if(my_module_description != null && my_module_description.flags != null && !my_module_description.flags.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Flags: " + this.normalize_html(my_module_description.flags).replace("\\", "\\\\") + "\" },");
				
				//
				//internal_name
				//
				if(my_module_description != null && my_module_description.internal_name != null && !my_module_description.internal_name.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Internal Name: " + this.normalize_html(my_module_description.internal_name).replace("\\", "\\\\") + "\" },");
				
				//
				//legal_trademarks
				//
				if(my_module_description != null && my_module_description.legal_trademarks != null && !my_module_description.legal_trademarks.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Legal Trademarks: " + this.normalize_html(my_module_description.legal_trademarks).replace("\\", "\\\\") + "\" },");
				
				//
				//copyright_legal_copyright
				//
				if(my_module_description != null && my_module_description.copyright_legal_copyright != null && !my_module_description.copyright_legal_copyright.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Copyright: " + this.normalize_html(my_module_description.copyright_legal_copyright).replace("\\", "\\\\") + "\" },");
				
				
				//
				//ole_self_register
				//
				if(my_module_description != null && my_module_description.ole_self_register != null && !my_module_description.ole_self_register.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"ole_self_register: " + this.normalize_html(my_module_description.ole_self_register).replace("\\", "\\\\") + "\" },");
										
				
				//
				//file_description
				//
				if(my_module_description != null && my_module_description.file_description != null && !my_module_description.file_description.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"File Description: " + this.normalize_html(my_module_description.file_description).replace("\\", "\\\\") + "\" },");
				
				//
				//product_version
				//
				if(my_module_description != null && my_module_description.product_version != null && !my_module_description.product_version.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Product Version: " + this.normalize_html(my_module_description.product_version).replace("\\", "\\\\") + "\" },");
				
				//
				//date_modified
				//
				if(my_module_description != null && my_module_description.date_modified != null && !my_module_description.date_modified.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Date Modified: " + this.normalize_html(my_module_description.date_modified).replace("\\", "\\\\") + "\" },");
				
				//
				//file_type
				//
				if(my_module_description != null && my_module_description.file_type != null && !my_module_description.file_type.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"File Type: " + this.normalize_html(my_module_description.file_type).replace("\\", "\\\\") + "\" },");
				
				//
				//file_size
				//
				if(my_module_description != null && my_module_description.file_size != null && !my_module_description.file_size.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"File Size (Header): " + this.normalize_html(my_module_description.file_size).replace("\\", "\\\\") + "\" },");
				
				//
				//language
				//
				if(my_module_description != null && my_module_description.language != null && !my_module_description.language.trim().equals(""))
					pw.println("\t\t\t" +  "{ \"name\": \"Produce Name: " + this.normalize_html(my_module_description.language).replace("\\", "\\\\") + "\" },");
			
			
			
			pw.println("\t\t" +  "]},");//end process information			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_process_information", e);
		}
		
		return false;
	}
	
	
	public String normalize_html(String value)
	{
		try
		{
			if(value == null)
				return "";
			
			//return value.replace("\"", "&#34;").replace("'", "&#39;").replace(";", "&#59;");//.replace("&", "&amp");
			return value.replace("\"", "").replace("'", "");//.replace("&", "&amp");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "normalize_html", e);
		}
		
		return value;
	}
	
	
	
	
	public boolean print_dll_import_table(PrintWriter pw)
	{
		try
		{
			for(Node_DLL dll : this.tree_dll.values())
			{
				if(dll == null)
					continue;
				
				pw.println("\n" + this.get_process_html_header());
				
				pw.println("\t" + dll.get_name());
				
				dll.print_import_funciton_names(this, pw, "\n\t\t");
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_dll_import_table", e);
		}
		
		return false;
	}
	
	
	public boolean write_table_process_information(PrintWriter pw) throws Exception
	{
		try
		{
			pw.print("<tr>");
			
				//https://www.hybrid-analysis.com/search?query=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
				
				pw.print(" <td> " + driver.normalize_html(""+PID).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.process_name).replace("\\", "&#92") + "</td>");
				
				if(this.fle_attributes != null)
				{
					fle_attributes.write_html_table_entries(pw);
				}
				else
				{
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
				}
				
				pw.print(" <td> " + driver.normalize_html(""+this.PPID).replace("\\", "&#92") + "</td>");
				
				if(parent_process != null)
					pw.print(" <td> " + driver.normalize_html(this.parent_process.process_name).replace("\\", "&#92") + "</td>");
				else
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
				
				pw.print(" <td> " + driver.normalize_html(this.time_created_date + " " + this.time_created_time).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.time_exited_date + " " + this.time_exited_time).replace("\\", "&#92") + "</td>");
				
				//pw.print(" <td> " + driver.normalize_html(Sibling Process(es)).replace("\\", "&#92") + "</td>");
				//pw.print(" <td> " + driver.normalize_html(Offspring Procces(es)).replace("\\", "&#92") + "</td>");
				
				pw.print(" <td> " + driver.normalize_html(this.path).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.command_line).replace("\\", "&#92") + "</td>");
				
				if(my_module_description != null)
					my_module_description.write_table_module_information(pw);
				else
				{
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					//pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					//pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					//pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					//pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					//pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					//pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
				}								
				
				//pw.print(" <td> " + driver.normalize_html(Import DLL(s)).replace("\\", "&#92") + "</td>");
				//pw.print(" <td> " + driver.normalize_html(Privileges).replace("\\", "&#92") + "</td>");
				
				
				
				pw.print(" <td> " + driver.normalize_html(this.threads).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.handles).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.session).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.wow64).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.PDB).replace("\\", "&#92") + "</td>");
								
				pw.print(" <td> " + driver.normalize_html(""+this.found_in_pslist).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(""+this.found_in_psscan).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.psxview_thrdproc).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.psxview_pspcid).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.psxview_csrss).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.psxview_session).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.psxview_deskthrd).replace("\\", "&#92") + "</td>");
				
				pw.print(" <td> " + driver.normalize_html(this.offset_pslist).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.offset_psscan).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.offset_psxview).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.offset_pstree).replace("\\", "&#92") + "</td>");
				
				//vadtree
				if(this.fle_vadtree_output_image != null && this.fle_vadtree_output_image.length() > 0)
					pw.print(" <td> " + "<a href=\"./../../" + this.relative_path_vadtree_image + "\" target=\"_blank\"> vadtree </a></td>");
				else
					pw.print(" <td> " + "-" + "</td>");
			
			
			pw.print("</tr>");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_process_information", e);
		}
		
		pw.print("<tr>");
		return false;
	}
	
	public boolean write_table_NETSTAT_information(PrintWriter pw)
	{
		try
		{
			if(this.tree_netstat == null || this.tree_netstat.isEmpty())
				return false;
									
			for(Node_Netstat_Entry node : this.tree_netstat.values())
			{
				try
				{
					if(node == null)
						continue;
					
					pw.print("<tr>");
					/////////////////////////////
					
					if(node.protocol == null || node.protocol.trim().equals(""))
						this.write_table_cell_entry(pw, "-");
					else
						this.write_table_cell_entry(pw, node.protocol);
					
					this.write_table_cell_entry(pw, node.local_address);
					this.write_table_cell_entry(pw, node.foreign_address);
					
					if(node.creation_date != null && !node.creation_date.trim().equals(""))
						this.write_table_cell_entry(pw, node.creation_date + " " + node.creation_time + " " + node.creation_utc);
					else
						this.write_table_cell_entry(pw, "-");
					
					
					
					this.write_table_cell_entry(pw, ""+PID);
					this.write_table_cell_entry(pw, this.process_name);
					
					if(node.state != null)
						this.write_table_cell_entry(pw, node.state);
					else
						this.write_table_cell_entry(pw, "-");
					
					this.write_table_cell_entry(pw, ""+this.PPID);
					
					if(this.parent_process != null)
						this.write_table_cell_entry(pw, this.parent_process.process_name);
					else
						this.write_table_cell_entry(pw, "-");
					
					if(node.is_foreign_address_private_or_non_routable() || node.foreign_address == null)
						this.write_table_cell_entry(pw, "-");
					else
					{
						String lookup = node.foreign_address.trim();
						
						if(lookup.contains("http://"))
							lookup = lookup.substring(7).trim();
						if(lookup.contains("https://"))
							lookup = lookup.substring(8).trim();
						if(lookup.contains("www."))
							lookup = lookup.substring(4).trim();
								
						if(lookup.contains(":"))
							lookup = lookup.substring(0, lookup.indexOf(":")).trim();
						
//						if(lookup.length() < 2)
//							return false;	
//						
//						pw.print(" <td> " + "<a href =\"https://www.virustotal.com/gui/ip-address/" + driver.normalize_html(lookup).replace("\\", "&#92") + "/detection\" target=\"_blank\"> Link </a></td>");
						
						if(lookup.length() > 3)
							pw.print(" <td> " + "<a href =\"https://www.virustotal.com/gui/ip-address/" + driver.normalize_html(lookup).replace("\\", "&#92") + "/detection\" target=\"_blank\"> Link </a></td>");
						else
							pw.print(" <td> " + "-" + "</td>");
					}
					
					
					
					////////////////////
					pw.print("</tr>");
					
				}
				catch(Exception e)
				{
					////////////////////
					pw.print("</tr>");
					continue;
				}
			}									
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_NETSTAT_information", e);
		}
		
		//pw.print("</tr>");
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

	
	
	
	public boolean write_table_TEMPLATE_information(PrintWriter pw)
	{
		try
		{
			pw.print("<tr>");
			/////////////////////////////
			
			
			this.write_table_cell_entry(pw, ""+this.PID);
			this.write_table_cell_entry(pw, this.process_name);
			
			if(this.fle_attributes != null)
				this.fle_attributes.write_html_table_entries(pw);
			else
			{
				pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
			}
			
			this.write_table_cell_entry(pw, ""+this.PPID);
			
			if(this.parent_process != null)
				this.write_table_cell_entry(pw, this.parent_process.process_name);
			
			
			////////////////////		
			pw.print("</tr>");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_TEMPLATE_information", e);
		}
		
		pw.print("</tr>");
		return false;
	}
	
	public boolean write_table_THREADS_information(PrintWriter pw)
	{
		try
		{
			if(this.tree_threads == null || this.tree_threads.size() < 1)
				return false;
			
			for(Node_Threads node : this.tree_threads.values())
			{
				try
				{
					pw.print("<tr>");
					/////////////////////////////
					
					this.write_table_cell_entry(pw, ""+this.PID);
					this.write_table_cell_entry(pw, this.process_name);
					
					if(this.fle_attributes != null)
						this.fle_attributes.write_html_table_entries(pw);
					else
					{
						pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
						pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
						pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
						pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
					}
					
					this.write_table_cell_entry(pw, ""+this.PPID);
					
					if(this.parent_process != null)
						this.write_table_cell_entry(pw, this.parent_process.process_name);
					else
						this.write_table_cell_entry(pw, "-");
					
					node.write_table_THREADS_information(pw);
					
					
					////////////////////
					pw.print("</tr>");
					
				}
				catch(Exception e)
				{
					
					////////////////////
					pw.print("</tr>");
					continue;
				}
				
			}
															
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_THREADS_information", e);
		}
		
		pw.print("</tr>");
		return false;
	}
	
	public boolean write_dependency_files_MALFIND_table(PrintWriter pw)
	{
		try
		{
			if(this.tree_malfind == null || this.tree_malfind.size() < 1)
				return false;
			
			for(Node_Malfind node : this.tree_malfind.values())
			{
				try
				{
					pw.print("<tr>");
					/////////////////////////////
					
					this.write_table_cell_entry(pw, ""+this.PID);
					this.write_table_cell_entry(pw, this.process_name);
					
					if(this.fle_attributes != null)
						this.fle_attributes.write_html_table_entries(pw);
					else
					{
						pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
						pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
						pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
						pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
					}
					
					this.write_table_cell_entry(pw, ""+this.PPID);
					
					if(this.parent_process != null)
						this.write_table_cell_entry(pw, this.parent_process.process_name);
					else
						this.write_table_cell_entry(pw, "-");
					
					node.write_dependency_files_MALFIND_table(pw);
					
					
					////////////////////
					pw.print("</tr>");
					
				}
				catch(Exception e)
				{
					
					////////////////////
					pw.print("</tr>");
					continue;
				}
				
			}
															
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_MALFIND_table", e);
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
	
	
	public boolean write_dependency_files_VADTREE_table(PrintWriter pw) throws Exception
	{
		try
		{
			if(this.fle_vadtree_output_image == null || !this.fle_vadtree_output_image.isFile() || !this.fle_vadtree_output_image.exists())
				return false;
			
			pw.print("<tr>");
			
				pw.print(" <td> " + driver.normalize_html(""+PID).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.process_name).replace("\\", "&#92") + "</td>");
				
				//vadtree
				if(this.fle_vadtree_output_image != null && this.fle_vadtree_output_image.length() > 0)
					pw.print(" <td> " + "<a href=\"./../../" + this.relative_path_vadtree_image + "\" target=\"_blank\"> vadtree </a></td>");
				else
					pw.print(" <td> " + "-" + "</td>");
				
				
				if(this.fle_attributes != null)
				{
					fle_attributes.write_html_table_entries(pw);
				}
				else
				{
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
				}
				
				pw.print(" <td> " + driver.normalize_html(""+this.PPID).replace("\\", "&#92") + "</td>");
				
				if(parent_process != null)
					pw.print(" <td> " + driver.normalize_html(this.parent_process.process_name).replace("\\", "&#92") + "</td>");
				else
					pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
				
				pw.print(" <td> " + driver.normalize_html(this.time_created_date + " " + this.time_created_time).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.time_exited_date + " " + this.time_exited_time).replace("\\", "&#92") + "</td>");
				
				pw.print(" <td> " + driver.normalize_html(this.path).replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html(this.command_line).replace("\\", "&#92") + "</td>");
															
			pw.print("</tr>");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_VADTREE_table", e);
		}
		
		pw.print("<tr>");
		return false;
	}
	
	public boolean write_vad_info_by_page_protection(String protection, PrintWriter pw)
	{
		try
		{
			
			
			if(protection == null)
				return false;
			
			
			
			if(this.tree_vad_page_protection == null)
				return false;
			
			
			
			LinkedList<Node_Generic> list = null;
			
			list = this.tree_vad_page_protection.get(protection);
			
			
			
			if(list == null)
				list = this.tree_vad_page_protection.get(protection.trim());
			
			if(list == null)
				list = this.tree_vad_page_protection.get(protection.toLowerCase());
			
			if(list == null)
				list = this.tree_vad_page_protection.get(protection.toLowerCase().trim());
			
			if(list == null)
				list = this.tree_vad_page_protection.get(protection.toUpperCase());
			
			if(list == null)
				list = this.tree_vad_page_protection.get(protection.toUpperCase().trim());
			
			if(list == null)
				return false;
			
			if(list.isEmpty())
				return false;
			
						
			int count = 0;
			pw.println("\t\t\t\t\t" +  "{ \"name\": \"" + this.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
			
				for(Node_Generic vad : list)
				{
					if(count % MAX_TREE_NODE_COUNT == 0 && count > 0)
					{
						pw.println("\t\t\t" +  "]},");
						
						pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
					}
					
					++count;
					
					if(vad == null)
						continue;
					
					String node_name = vad.offset;
					
					if(vad.name != null && vad.name.trim().length() > 2)
						node_name = vad.name.trim() + " " + vad.offset;
					
					pw.println("\t\t\t" +  "{ \"name\": \"" + this.normalize_html(node_name).replace("\\", "\\\\") + "\" , \"children\": [");
					
					driver.write_EXPANDED_node_ENTRY("Process", this.get_process_html_header(), pw);
					driver.write_EXPANDED_node_ENTRY("Name", vad.name, pw);
					driver.write_EXPANDED_node_ENTRY("Path", vad.path, pw);
					
					if(vad.list_details != null)
					{
						pw.println("\t\t\t\t" +  "{ \"name\": \"" + this.normalize_html("Details").replace("\\", "\\\\") + "\" , \"children\": [");
						
						for(String entry : vad.list_details)
						{						
							driver.write_node_ENTRY("", entry, pw);
						}
						
						pw.println("\t\t\t\t" +  "]},");
					}
					
					pw.println("\t\t\t" +  "]},");
					
				}//end for
			
			pw.println("\t\t\t\t\t" +  "]},");	
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_vad_info_by_page_protection", e);
		}
		
		return false;
	}
	
	
	/**Write PROCESS header and underline about this process when a hit is found, however only do this once per XREF search.  This function is to 
	 * simplify the code such that I don't have to check this value each time*/
	public boolean write_process_header_for_XREF_hit(JTextArea_Solomon jta)
	{
		try
		{
			if(I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY)
				return true;					
			
			//hit found!
			if(jta != null)
				jta.append("Process: " + this.get_process_html_header() + "\n" + driver.UNDERLINE);
			
			I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = true;
			
			/*if(this.parent_process != null)
				jta.append("Parent Process: " + this.parent_process.get_process_html_header());
			else if(this.PPID > -1)
				jta.append("PPID: " + this.parent_process.get_process_html_header());*/									
		}
		catch(Exception e)
		{
			driver.eop(this.myClassName, "write_header_for_XREF_hit",  e);
		}
		
		return false;
	}
	
	public boolean append_to_jta_XREF(String out, JTextArea_Solomon jta)
	{
		try
		{
			XREF_SEARCH_HIT_FOUND = true;
			
			if(jta == null)
				return false;
			
			write_process_header_for_XREF_hit(jta);
			jta.append(out);			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "append_to_jta_XREF", e);
		}
		
		return false;
	}
	
	public boolean search_XREF(String search_chars_from_user, String search_chars_from_user_lower, JTextArea_Solomon jta)
	{
		try
		{
			XREF_SEARCH_HIT_FOUND = false;
			I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = false;
			
			//parent process name
			if(this.parent_process != null && this.parent_process.get_process_html_header().toLowerCase().contains(search_chars_from_user_lower))
				append_to_jta_XREF("Parent Process: " + parent_process.get_process_html_header(), jta);
			
			//search own process name
			if(this.get_process_html_header().toLowerCase().contains(search_chars_from_user_lower))
				append_to_jta_XREF("Process Name: " + get_process_html_header(), jta);
				
			////////////////////////////////////////////////////////
			//
			//Strings
			//
			//////////////////////////////////////////////////////////
			
			try
			{
				if(command_line != null && command_line.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Command Line: " + this.command_line, jta);
				if(path != null && path.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Path: " + this.path, jta);
				if(threads  != null && threads .toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Thread Count: " + this.threads , jta);
				if(handles != null && handles.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Handle Count: " + this.handles, jta);
				if(wow64 != null && wow64.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Wow64: " + this.wow64, jta);
				if(session != null && session.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Session: " + this.session, jta);
				if(offset_pslist != null && offset_pslist.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("PSList Offset: " + this.offset_pslist, jta);
				if(PDB != null && PDB.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("PDB: " + this.PDB, jta);
				if(time_created_date != null && time_created_date.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Creation Date: " + this.time_created_date, jta);
				if(time_created_time != null && time_created_time.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Creation Time: " + this.time_created_time, jta);
				if(time_created_UTC != null && time_created_UTC.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("UTC Creation Time: " + this.time_created_UTC, jta);
				if(time_exited_date != null && time_exited_date.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Date Exited: " + this.time_exited_date, jta);
				if(time_exited_time != null && time_exited_time.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Time Exited: " + this.time_exited_time, jta);
				if(time_exited_UTC != null && time_exited_UTC.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("UTC Time Exited: " + this.time_exited_UTC, jta);
				if(offset_psscan != null && offset_psscan.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("PSScan Offset: " + this.offset_psscan, jta);
				if(offset_pstree != null && offset_pstree.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("PSTree Offset: " + this.offset_pstree, jta);
				if(offset_psxview != null && offset_psxview.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("PSXview Offset: " + this.offset_psxview, jta);
				if(psxview_pslist != null && psxview_pslist.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("PSXview - Pslist: " + this.psxview_pslist, jta);
				if(psxview_psscan != null && psxview_psscan.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("PSXview - PSScan: " + this.psxview_psscan, jta);
				if(psxview_thrdproc != null && psxview_thrdproc.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("PSXview - thrdproc: " + this.psxview_thrdproc, jta);
				if(psxview_pspcid != null && psxview_pspcid.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("PSXview - pspcid: " + this.psxview_pspcid, jta);
				if(psxview_csrss != null && psxview_csrss.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("PSXview - csrss: " + this.psxview_csrss, jta);
				if(psxview_session != null && psxview_session.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("PSXview - session: " + this.psxview_session, jta);
				if(psxview_deskthrd != null && psxview_deskthrd.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("PSXview - deskthrd: " + this.psxview_deskthrd, jta);
				if(offset_V_dlldump  != null && offset_V_dlldump .toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("DLLDump - Offset (V): " + this.offset_V_dlldump , jta);
				if(offset_P_dlldump_trimmed  != null && offset_P_dlldump_trimmed .toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("DLLDump - Offset (P) - Trimmed: " + this.offset_P_dlldump_trimmed , jta);
				if(module_base_address_dlldump  != null && module_base_address_dlldump .toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("DLLDump Module Base Address: " + this.module_base_address_dlldump , jta);
				if(module_base_address_dlldump_trimmed != null && module_base_address_dlldump_trimmed.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("DLLDump Module Base Address - Trimmed: " + this.module_base_address_dlldump_trimmed, jta);
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate attributes of " + this.get_process_html_header());
			}
			
			//////////////////////////////////////////////////////////
			//
			//my VAD info
			//
			//////////////////////////////////////////////////////////
			if(VAD != null)
				VAD.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "My VAD Info");
						
			//////////////////////////////////////////////////////////
			//
			//search handles
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(tree_handles != null)
				{
					for(Node_Handle handle: tree_handles.values())
					{
						if(handle == null)
							continue;
							
							handle.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "Handles");
					}
				}
				
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_handles");
			}
			
			
			//////////////////////////////////////////////////////////
			//
			//Netstat
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(tree_netstat != null)
				{
					for(Node_Netstat_Entry node: tree_netstat.values())
					{
						if(node == null)
							continue;
							
							node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "Netstat");
					}
				}
				
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_netstat");
			}
			
			
			//////////////////////////////////////////////////////////
			//
			//Netstat
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(tree_netstat != null)
				{
					for(Node_Netstat_Entry node: tree_netstat.values())
					{
						if(node == null)
							continue;
							
							node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "Netstat");
					}
				}
				
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_netstat");
			}
			
			
			//////////////////////////////////////////////////////////
			//
			//tree_privs
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(tree_privs != null)
				{
					for(Node_Privs node: tree_privs.values())
					{
						if(node == null)
							continue;
							
							node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "Privileges");
					}
				}
				
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_privs");
			}
			
			//////////////////////////////////////////////////////////
			//
			//tree_services_svcscan
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(tree_services_svcscan != null)
				{
					for(Node_svcscan node: tree_services_svcscan.values())
					{
						if(node == null)
							continue;
							
							node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "Services");
					}
				}
				
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_services_svcscan");
			}
			
			//////////////////////////////////////////////////////////
			//
			//tree_threads
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(tree_threads != null)
				{
					for(Node_Threads node: tree_threads.values())
					{
						if(node == null)
							continue;
							
							node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "Threads");
					}
				}
				
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_threads");
			}
			
			//////////////////////////////////////////////////////////
			//
			//tree_gdi_timers
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(tree_gdi_timers != null)
				{
					for(Node_Generic node: tree_gdi_timers.values())
					{
						if(node == null)
							continue;
							
							node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "GDI Timers");
					}
				}
				
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_gdi_timers");
			}
			
			//////////////////////////////////////////////////////////
			//
			//tree_api_hook
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(tree_api_hook != null)
				{
					for(Node_ApiHook node: tree_api_hook.values())
					{
						if(node == null)
							continue;
							
							node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "API Hooks");
					}
				}
				
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_api_hook");
			}
			
			//////////////////////////////////////////////////////////
			//
			//tree_deskscan
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(tree_deskscan != null)
				{
					for(TreeMap<String, Node_Generic> tree: this.tree_deskscan.values())
					{
						if(tree == null || tree.isEmpty())
							continue;
							
						for(Node_Generic node: tree.values())
						{
							if(tree == null || tree.isEmpty())
								continue;
						
							node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "Deskscan");
						}
					}
				}
				
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_deskscan");
			}
			
			//////////////////////////////////////////////////////////
			//
			//tree_impscan_DLL_containers
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(tree_impscan_DLL_containers != null)
				{
					for(Node_DLL_Container_Impscan node: tree_impscan_DLL_containers.values())
					{
						if(node == null)
							continue;

						node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "ImpScan");
					}
				}

			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_impscan_DLL_containers");
			}

			//////////////////////////////////////////////////////////
			//
			//tree_cmdscan_consoles
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(tree_cmdscan_consoles != null)
				{
					for(Node_CmdScan node: tree_cmdscan_consoles.values())
					{
						if(node == null)
							continue;

						node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "Consoles");
					}
				}

			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_cmdscan_consoles");
			}
			

			//////////////////////////////////////////////////////////
			//
			//tree_environment_vars
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(tree_environment_vars != null)
				{
					for(Node_Envar node: tree_environment_vars.values())
					{
						if(node == null)
							continue;

						node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "Environment Vars");
					}
				}

			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_environment_vars");
			}
			
			//////////////////////////////////////////////////////////
			//
			//tree_vad_page_protection
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(tree_vad_page_protection != null)
				{
					for(LinkedList<Node_Generic> list : tree_vad_page_protection.values())
					{
						if(list == null)
							continue;
						
						for(Node_Generic node: list)
						{
							if(node == null)
								continue;

							node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "VAD Page Protection");
						}						
					}										
				}
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_vad_page_protection");
			}
			
			//////////////////////////////////////////////////////////
			//
			//list_cmd_scan
			//
			//////////////////////////////////////////////////////////			
			try
			{
				if(list_cmd_scan != null)
				{
					for(Node_CmdScan node : list_cmd_scan)
					{
						if(node == null)
							continue;

						node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "Command Scan");
					}
				}

			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through list_cmd_scan");
			}
			
			
			//////////////////////////////////////////////////////////
			//
			//DLLs
			//
			//////////////////////////////////////////////////////////
			
			try
			{
				if(this.tree_dll != null && tree_dll.size() > 0)
				{
					for(Node_DLL dll : tree_dll.values())
					{
						if(dll == null)
							continue;
						
						if(dll.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, false, this, null, null, "DLL"))
							XREF_SEARCH_HIT_FOUND = true;
								
					}
				}
				
			}//end try
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_DLL");
			}
				
//			////////////////////////////////////////////////////////
//			//
//			//search imports
//			//NOTE: only checking function names at this time
//			//
//			//////////////////////////////////////////////////////////
//			
//			try
//			{
//				if(this.tree_impscan_DLL_containers != null && this.tree_impscan_DLL_containers.size() > 0)
//				{
//					for(Node_DLL_Container_Impscan dll : this.tree_impscan_DLL_containers.values())
//					{
//						if(dll == null)
//							continue;
//						
//						//search import functions
//						if(dll.tree_impscan_functions == null)
//							continue;
//						
//						for(String function_name : dll.tree_impscan_functions.keySet())
//						{
//							if(function_name != null && function_name.toLowerCase().trim().contains(search_chars_from_user_lower))
//							{
//								this.append_to_jta_XREF("DLL: " + dll.module_name + " Import Function: " + function_name, jta);
//							}
//						}																								
//					}
//				}
//			
//			}//end try
//			catch(Exception e)
//			{
//				driver.sop("NOTE: I could not properly iterate through tree_impscan_DLL_containers");
//			}
			

			//////////////////////////////////////////////////////////
			//
			//tree_sids
			//
			//////////////////////////////////////////////////////////
			
			try
			{
				if(this.tree_sids != null)
				{
					String value = "";
					
					for(String key : tree_sids.keySet())
					{
						if(key == null)
							continue;
						
						try	{	value = tree_sids.get(key); } catch(Exception e){ value = "";}
						
						if(key.toLowerCase().trim().contains(search_chars_from_user_lower) || value.toLowerCase().trim().contains(search_chars_from_user_lower))
							this.append_to_jta_XREF("SID: " + key + "\t" + value, jta);
					}
				}
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_sids");
			}
			
			

			
			//////////////////////////////////////////////////////////
			//
			//tree_malfind
			//
			//////////////////////////////////////////////////////////
			try
			{
				if(this.tree_malfind != null)
				{										
					Node_Malfind node = null;
					
					for(String key : tree_malfind.keySet())
					{
						if(key == null)
							continue;
								
						node = tree_malfind.get(key);
						
						if(node == null)
							continue;
						
						//
						//iterate through node for xref string
						//solo, ensure key is a value searched in respective xref function
						//
						node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this);
					}
				}
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_malfind");
			}
			
			//////////////////////////////////////////////////////////
			//
			//tree_vad_info
			//
			//////////////////////////////////////////////////////////
			try
			{
				if(this.tree_vad_info != null)
				{																	
					for(Node_Generic node : tree_vad_info.values())
					{
						if(node == null)
							continue;
						
						if(this.VAD != null && node == this.VAD)
							continue;
								
						node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, this, "VAD Info");
					}
				}
			}
			catch(Exception e)
			{
				driver.sop("NOTE: I could not properly iterate through tree_vad_info");
			}
			
			if(fle != null)
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle.getCanonicalPath(), "File", search_chars_from_user, search_chars_from_user_lower, jta, this, "DLL");
			
			///////////////////////////////////////////////////////////////////////
			//
			//File Attributes
			//
			//////////////////////////////////////////////////////////////////////
			if(this.fle_attributes != null)
			{
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.creation_date, "File Creation Date", search_chars_from_user, search_chars_from_user_lower, jta, this, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.extension, "File Extension", search_chars_from_user, search_chars_from_user_lower, jta, this, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.file_name, "File Name", search_chars_from_user, search_chars_from_user_lower, jta, this, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_md5, "File Hash - MD5", search_chars_from_user, search_chars_from_user_lower, jta, this, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_sha256, "File Hash - Sha256", search_chars_from_user, search_chars_from_user_lower, jta, this, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_accessed, "FileLast Accessed", search_chars_from_user, search_chars_from_user_lower, jta, this, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_modified, "File Last Modified", search_chars_from_user, search_chars_from_user_lower, jta, this, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.size, "File Size", search_chars_from_user, search_chars_from_user_lower, jta, this, "File Attributes");
			}						
			
			
			
			
			return XREF_SEARCH_HIT_FOUND;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "search_XREF", e);
		}
		
		return false;
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
	
	
	public boolean check_to_display_consoles()
	{
		try
		{
			if(list_cmd_scan == null || list_cmd_scan.size() < 0)
				return false;
			
			if(jtaConsolesOutput == null)
			{
				jtaConsolesOutput = new JTextArea_Solomon("", true, "Consoles - " + this.get_process_html_header(), false);	
				
				Start.intface.populate_export_btn(jtaConsolesOutput);
			}
			
			if(!consoles_has_been_added_to_gui)
			{
				try
				{
					Start.intface.jtabbedpane_AdvancedAnalysis.addTab("Console Output - " + this.get_process_html_header(), jtaConsolesOutput);
					consoles_has_been_added_to_gui = true;	
				}
				catch(Exception e)
				{
					driver.directive("Note: I encountered difficulty updating GUI with Consoles - " + this.get_process_html_header());
				}
				
			}
			
			jtaConsolesOutput.clear();
			
			jtaConsolesOutput.append("PROCESS\n" + driver.UNDERLINE);
			jtaConsolesOutput.append(this.get_process_html_header());
			jtaConsolesOutput.append("\n");
			
			try
			{
				if(this.parent_process != null)
				{
					jtaConsolesOutput.append("PARENT PROCESS\n" + driver.UNDERLINE);
					jtaConsolesOutput.append(this.parent_process.get_process_html_header());
					jtaConsolesOutput.append("\n");
				}
				else if(this.PPID > -1)
				{
					jtaConsolesOutput.append("PPID\n" + driver.UNDERLINE);
					jtaConsolesOutput.append(""+this.PPID);
					jtaConsolesOutput.append("\n");
				}
			}catch(Exception e){}			
			
			
			if(this.command_line != null && this.command_line.length() > 0)
			{
				jtaConsolesOutput.append("COMMAND LINE\n" + driver.UNDERLINE);
				jtaConsolesOutput.append(this.command_line);
				jtaConsolesOutput.append("\n");
			}
			
			jtaConsolesOutput.append("COMMAND HISTORY COUNT\n" + driver.UNDERLINE);
			jtaConsolesOutput.append("" + list_cmd_scan.size());
			jtaConsolesOutput.append("\n");
			
			int cmd_history_count = 0;
			
			for(Node_CmdScan cmd : this.list_cmd_scan)
			{
				if(cmd == null)
					continue;											
				
					//header
					jtaConsolesOutput.append("HISTORY [" + cmd_history_count + "] COMMAND HEADER\n" + driver.UNDERLINE);
					
					for(String element : cmd.list_cmd_header)
					{
						if(element == null || element.toLowerCase().trim().equals("null"))
							continue;
						
						jtaConsolesOutput.append(element);
					}
					jtaConsolesOutput.append("\n");
					
					
					jtaConsolesOutput.append("COMMAND DETAILS\n" + driver.UNDERLINE);
					
					for(String element : cmd.list_cmd_details)
					{
						if(element == null || element.toLowerCase().trim().equals("null"))
							continue;
						
						jtaConsolesOutput.append(element);
					}
					jtaConsolesOutput.append("\n");
					
					
					
					//console output
					if(cmd.list_consoles_output != null && cmd.list_consoles_output.size() > 0)
					{
						//consoles
						jtaConsolesOutput.append("CONSOLE OUTPUT\n" + driver.UNDERLINE);
						
						for(String element : cmd.list_consoles_output) 
						{
							if(element == null || element.toLowerCase().trim().equals("null"))
								continue;
							
							jtaConsolesOutput.append(element);
						}
						jtaConsolesOutput.append("\n");
					}										
				
			}//end for loop
															
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "check_to_display_consoles", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	public boolean write_manifest(PrintWriter pw)
	{
		try
		{
			if(pw == null)
				return false;
			
			//public volatile Node_DLL my_module_description = null;
			//public volatile TreeMap<String, Node_DLL> tree_import_functions_DEPRECATED = new TreeMap<String, Node_DLL>();
			/**linked by DLL path*/
			//public volatile TreeMap<String, Node_DLL> tree_dll = new TreeMap<String, Node_DLL>();
			/**linked by DLL VAD_base_start address*/
			//public volatile TreeMap<String, Node_DLL> tree_dll_VAD_base_start_address = new TreeMap<String, Node_DLL>();
			
			
			
			//not needed?
			//public volatile boolean alert_user_regarding_presence_of_console = false;
			//public volatile File fle_vadtree_output_data = null;
			//public volatile File fle_vadtree_output_image = null;
			//public volatile JTextArea_Solomon jtaConsolesOutput = null;
			//public volatile boolean consoles_has_been_added_to_gui = false;
							
			driver.write_manifest_entry(pw, "PID", ""+PID);
			driver.write_manifest_entry(pw, "process_name", process_name);
			driver.write_manifest_entry(pw, "PPID", ""+PPID);
			driver.write_manifest_entry(pw, "command_line", command_line);
			
			driver.write_manifest_entry(pw, "file_name", file_name);			
			driver.write_manifest_entry(pw, "extension", extension);
			
			if(my_module_description != null)
			{
				my_module_description.write_manifest_basic("my_module_description", pw);
				pw.println(Driver.END_OF_ENTRY_MINOR);
			}
			
			if(fle_attributes != null)
			{
				fle_attributes.write_manifest_entry(pw, "process\tfile_attr\t", null);
				pw.println(Driver.END_OF_ENTRY_MINOR);
			}
			
			//
			//pslist
			//			
			driver.write_manifest_entry(pw, "thread_count", threads);
			driver.write_manifest_entry(pw, "handle_count", handles);
			driver.write_manifest_entry(pw, "wow64", wow64);
			driver.write_manifest_entry(pw, "session", session);
			driver.write_manifest_entry(pw, "offset_pslist", offset_pslist);
						
			//
			//psscan
			//
			driver.write_manifest_entry(pw, "PDB", PDB);
			driver.write_manifest_entry(pw, "time_created_date", time_created_date);
			driver.write_manifest_entry(pw, "time_created_time", time_created_time);
			driver.write_manifest_entry(pw, "time_created_UTC", time_created_UTC);
			driver.write_manifest_entry(pw, "time_exited_date", time_exited_date);
			driver.write_manifest_entry(pw, "time_exited_time", time_exited_time);
			driver.write_manifest_entry(pw, "time_exited_UTC", time_exited_UTC);
			driver.write_manifest_entry(pw, "offset_psscan", offset_psscan);
			
			//
			//pstree
			//
			driver.write_manifest_entry(pw, "offset_pstree", offset_pstree);
			
			//
			//psxview
			//
			driver.write_manifest_entry(pw, "offset_psxview", offset_psxview);
			driver.write_manifest_entry(pw, "psxview_pslist", psxview_pslist);
			driver.write_manifest_entry(pw, "psxview_psscan", psxview_psscan);
			driver.write_manifest_entry(pw, "psxview_thrdproc", psxview_thrdproc);
			driver.write_manifest_entry(pw, "psxview_pspcid", psxview_pspcid);
			driver.write_manifest_entry(pw, "psxview_csrss", psxview_csrss);
			driver.write_manifest_entry(pw, "psxview_session", psxview_session);
			driver.write_manifest_entry(pw, "psxview_deskthrd", psxview_deskthrd);
						
			//
			//dlldump
			//
			driver.write_manifest_entry(pw, "offset_V_dlldump", offset_V_dlldump);
			driver.write_manifest_entry(pw, "offset_P_dlldump_trimmed", offset_P_dlldump_trimmed);
			driver.write_manifest_entry(pw, "module_base_address_dlldump", module_base_address_dlldump);
			driver.write_manifest_entry(pw, "module_base_address_dlldump_trimmed", module_base_address_dlldump_trimmed);
			
			//
			//dlllist
			//
			driver.write_manifest_entry(pw, "path", path);
			
			//
			//other
			//
			driver.write_manifest_entry(pw, "found_in_pslist", ""+found_in_pslist);
			driver.write_manifest_entry(pw, "found_in_psscan", ""+found_in_psscan);
			driver.write_manifest_entry(pw, "relative_path_vadtree_image", relative_path_vadtree_image);
			
			pw.println(Driver.END_OF_ENTRY_MINOR);
			
			//
			//my vad
			//
			try	{	if(this.VAD != null)	VAD.write_manifest(pw, "my_vad_info", "\t", false, false, true);			}	catch(Exception e){}
				
			
			//
			//netstat
			//
			write_manifest_netstat(pw);
			
			//
			//Handles
			//
			write_manifest_handles(pw, this.tree_handles);
			
			//
			//Privs
			//
			write_manifest_privilege(pw, this.tree_privs, "privilege", driver.delimiter);
			
			//
			//Service Scan
			//
			write_manifest_svcscan(pw, this.tree_services_svcscan, "svcscan", driver.delimiter);
			
			//
			//SIDS
			//
			write_manifest_STRING(pw, this.tree_sids, "sids", driver.delimiter, true, false, false);
			
			//
			//malfind
			//
			write_manifest_malfind(pw, this.tree_malfind, "malfind", driver.delimiter);
			
			//
			//threads
			//
			write_manifest_threads(pw, this.tree_threads, "threads", driver.delimiter);
			
			//
			//GDI Timers
			//
			write_manifest_Node_Generic(pw, this.tree_gdi_timers, "gdi_timers", driver.delimiter, true);
			
			//
			//APIHooks
			//
			write_manifest_api_hooks(pw, this.tree_api_hook, "api_hooks", driver.delimiter);
			
			
			//			
			//vad_info
			//
			write_manifest_Node_Generic(pw, this.tree_vad_info, "vad_info", driver.delimiter, false);
			
			//
			//deskscan
			//
			//NOTE: don't do this process deskscan, we'll link all deskcans with the main tree_deskscan that describes the processes
			//write_manifest_deskscan_DEPRECATED(pw, this.tree_deskscan, "process deskscan", driver.delimiter, false);
			
			//
			//list_cmd_scan
			//
			write_manifest_cmdscan(pw, this.list_cmd_scan, "cmdscan", driver.delimiter, false);
			
			
			//
			//tree_cmdscan_consoles
			//
			write_manifest_cmdscan_consoles(pw, this.tree_cmdscan_consoles, "cmdscan_consoles", driver.delimiter, false);

			//			
			//envars
			//
			write_manifest_envars(pw, this.tree_environment_vars, "envars", driver.delimiter, true);
			
			//
			//import functions
			//
			write_manifest_impscan(pw, this.tree_impscan_DLL_containers, "impscan", driver.delimiter);
			
			pw.println(driver.END_OF_ENTRY_MAJOR);
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest", e);
		}
		
		pw.println(driver.END_OF_ENTRY_MAJOR);
		return false;
	}
	
	
	public boolean write_manifest_impscan(PrintWriter pw,TreeMap<String, Node_DLL_Container_Impscan> tree, String header, String delimiter)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(tree == null || tree.isEmpty())
				return false;
			
			boolean include_underline = (tree.size() > 1);
			
			for(Node_DLL_Container_Impscan node : tree.values())
			{
				if(node == null)
					continue;

				node.write_manifest(pw, header, delimiter, include_underline);			
				
			}			
			
			if(!include_underline)
				pw.println(Driver.END_OF_ENTRY_MINOR);
						
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_Node_Generic of type " + header, e);
		}
		
		return false;
	}
	
	public boolean write_manifest_envars(PrintWriter pw,TreeMap<String, Node_Envar> tree, String header, String delimiter, boolean print_output_as_single_line)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(tree == null || tree.isEmpty())
				return false;
			
			boolean include_underline = (tree.size() > 1);
			
			for(Node_Envar node : tree.values())
			{
				if(node == null)
					continue;

				node.write_manifest(pw, header, delimiter, include_underline, print_output_as_single_line);			}			
			
			
			pw.println(Driver.END_OF_ENTRY_MINOR);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_Node_Generic of type " + header, e);
		}
		
		return false;
	}
	
	public boolean write_manifest_cmdscan_consoles(PrintWriter pw, TreeMap<String, Node_CmdScan> tree, String header, String delimiter, boolean print_output_as_single_line)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(tree == null || tree.isEmpty())
				return false;
			
			boolean include_underline = (tree.size() > 1);
			
			for(Node_CmdScan node  : tree.values())
			{
				if(node == null)
					continue;
								
				node.write_manifest(pw, header, delimiter, include_underline, print_output_as_single_line);
			}	
			
			if(!include_underline)
				pw.println(Driver.END_OF_ENTRY_MINOR);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_");
		}
		
		return false;
	}
	
	
	public boolean write_manifest_cmdscan(PrintWriter pw, LinkedList<Node_CmdScan> list, String header, String delimiter, boolean print_output_as_single_line)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(list == null)
				return false;
			
			boolean include_underline = (list.size() > 1);
			
			for(Node_CmdScan node  : list)
			{
				if(node == null)
					continue;				
				
				node.write_manifest(pw, header, delimiter, include_underline, print_output_as_single_line);				
			}	
			
			if(!include_underline)
				pw.println(Driver.END_OF_ENTRY_MINOR);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_");
		}
		
		return false;
	}
	
	public boolean write_manifest_deskscan_DEPRECATED(PrintWriter pw, TreeMap<String, TreeMap<String, Node_Generic>> tree, String header, String delimiter, boolean print_output_as_single_line)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(tree == null || tree.isEmpty())
				return false;
			
			boolean include_underline = (tree.size() > 1);
			
			for(TreeMap<String, Node_Generic> tree_deskscan  : tree.values())
			{
				if(tree_deskscan == null || tree_deskscan.isEmpty())
					continue;
				
				for(Node_Generic node : tree_deskscan.values())
				{
					if(node == null)
						continue;

					node.write_manifest(pw, header, delimiter, include_underline, print_output_as_single_line, true);	
				}
				
			}			
			
			if(!include_underline)
				pw.println(Driver.END_OF_ENTRY_MINOR);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_");
		}
		
		return false;
	}
	
	
	public boolean write_manifest_api_hooks(PrintWriter pw, TreeMap<String, Node_ApiHook> tree, String header, String delimiter)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(tree == null || tree.isEmpty())
				return false;
			
			boolean include_underline = (tree.size() > 1);
			
			for(Node_ApiHook node : tree.values())
			{
				if(node == null)
					continue;

				node.write_manifest(pw, header, delimiter, include_underline);			
				
			}			
			
			if(!include_underline)
				pw.println(Driver.END_OF_ENTRY_MINOR);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_" + header, e);
		}
		
		return false;
	}
	
	
	public boolean write_manifest_Node_Generic(PrintWriter pw, TreeMap<String, Node_Generic> tree, String header, String delimiter, boolean print_output_as_single_line)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(tree == null || tree.isEmpty())
				return false;
			
			boolean include_underline = (tree.size() > 1);
			
			for(Node_Generic node : tree.values())
			{
				if(node == null)
					continue;

				node.write_manifest(pw, header, delimiter, include_underline, print_output_as_single_line, true);			
						
			}			
			
			if(!include_underline)
				pw.println(Driver.END_OF_ENTRY_MINOR);
						
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_Node_Generic of type " + header, e);
		}
		
		return false;
	}
	
	public boolean write_manifest_threads(PrintWriter pw, TreeMap<String, Node_Threads> tree, String header, String delimiter)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(tree == null || tree.isEmpty())
				return false;
			
			boolean include_underline = (tree.size() > 1);
			
			for(Node_Threads node : tree.values())
			{
				if(node == null)
					continue;

				//do not output as single line bcs Threads could inlcude "eax=0x006ef490 ebx=0x006ef9f4 ecx=0x00000007 edx=0x0000007a esi=0x00000003 edi=0x00000000" e.g. Malware Analysis Engineering Sample 14.1
				node.write_manifest(pw, header, delimiter, include_underline);			
				
			}				
			
								
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_" + header, e);
		}
		
		return false;
	}
	
	
	public boolean write_manifest_malfind(PrintWriter pw, TreeMap<String, Node_Malfind> tree, String header, String delimiter)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(tree == null || tree.isEmpty())
				return false;
			
			boolean include_underline = (tree.size() > 1);
			
			for(Node_Malfind node : tree.values())
			{
				if(node == null)
					continue;

				node.write_manifest(pw, header, delimiter, include_underline);			
				
			}					
			
			if(!include_underline)
				pw.println(Driver.END_OF_ENTRY_MINOR);
				
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_" + header, e);
		}
		
		return false;
	}
	
	public boolean write_manifest_STRING(PrintWriter pw, TreeMap<String, String> tree, String header, String delimiter, boolean include_key_and_value, boolean include_key_ONLY, boolean include_value_ONLY)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(tree == null || tree.isEmpty())
				return false;
			
			String value = "";
			
			for(String key : tree.keySet())
			{
				if(key == null)
					continue;
				
				try	{	value = tree.get(key);}	catch(Exception e){value = "";}

				if(include_key_and_value)
					driver.write_manifest_entry(pw, header, key, value);
				else if(include_key_ONLY)
					driver.write_manifest_entry(pw, header, key);
				else if(include_value_ONLY)
					driver.write_manifest_entry(pw, header, value);				
			}			
			
			pw.println(Driver.END_OF_ENTRY_MINOR);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_STRING for type:" + header, e);
		}
		
		return false;
	}
	
	public boolean write_manifest_privilege(PrintWriter pw, TreeMap<String, Node_Privs> tree, String header, String delimiter)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(tree == null || tree.isEmpty())
				return false;
			
			for(Node_Privs node : tree.values())
			{
				if(node == null)
					continue;

				node.write_manifest(pw, header, delimiter);			
				
			}			
			
			pw.println(Driver.END_OF_ENTRY_MINOR);
						
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_" + header, e);
		}
		
		return false;
	}
	
	public boolean write_manifest_svcscan(PrintWriter pw, TreeMap<String, Node_svcscan> tree, String header, String delimiter)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(tree == null || tree.isEmpty())
				return false;
			
			for(Node_svcscan node : tree.values())
			{
				if(node == null)
					continue;

				node.write_manifest(pw, header, delimiter);			
				
			}					
			
			pw.println(Driver.END_OF_ENTRY_MINOR);
				
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_" + header, e);
		}
		
		return false;
	}
	
	public boolean write_manifest_netstat(PrintWriter pw)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(tree_netstat != null)
			{
				for(Node_Netstat_Entry netstat : tree_netstat.values())
				{
					if(netstat == null)
						continue;
					
					netstat.write_manifest(pw, "netstat", "\t", ":");
				}
			}			
			
			pw.println(Driver.END_OF_ENTRY_MINOR);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_netstat", e);
		}
		
		return false;
	}
	
	public boolean write_manifest_handles(PrintWriter pw, TreeMap<String, Node_Handle> tree)
	{
		try
		{
			if(pw == null || tree == null || tree.isEmpty())
				return false;
			
			for(Node_Handle handle : tree.values())
			{
				if(handle == null)
					continue;
				
				driver.write_manifest_entry(pw, "handle", handle.get_manifest_file_entry("\t"));
			}			
			
			pw.println(Driver.END_OF_ENTRY_MINOR);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_handles", e);
		}
		
		return false;
	}
	
	
	public boolean write_manifest_child_process(PrintWriter pw)
	{
		try
		{
			if(pw == null || tree_child_process == null || tree_child_process.isEmpty())
				return false;
			
			String child_process_list = "";			
			
			LinkedList<Integer> list_child_process = new LinkedList<Integer>(this.tree_child_process.keySet());
			
			if(list_child_process == null || list_child_process.isEmpty())
				return false;
			
			//write processes
			child_process_list = ""+list_child_process.removeFirst();
			
			//accumulate pid list
			for(int child_pid : list_child_process)
			{
				child_process_list = child_process_list + ", " + child_pid;
			}
			
			//write data
			pw.println("child_process\t " + this.PID + "\t=\t" + child_process_list);
												
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_child_process", e);
		}
		
		return false;
	}
	
	
	public String get_deskscan_manifest_thread_list(String desktop_offset)
	{
		try
		{
			if(this.tree_deskscan == null || this.tree_deskscan.isEmpty() || !this.tree_deskscan.containsKey(desktop_offset))
				return null;
				
			//Locate the Desktop
			TreeMap<String, Node_Generic> tree_DESKTOP = tree_deskscan.get(desktop_offset);
			
			if(tree_DESKTOP == null)
				return null;
			
			//each entry is the thread ID for this process
			LinkedList<String> list = new LinkedList<String>(tree_DESKTOP.keySet());
			
			if(list == null || list.isEmpty())
				return null;
			
			String thread_list = list.removeFirst();
			
			for(String thread_id : list)
			{
				if(thread_id == null || thread_id.trim().equals(""))
					continue;
				
				if(!thread_list.contains(thread_id))
					thread_list = thread_list + ", " + thread_id;
			}
			
			return "PID:\t " + this.PID + "\t thread_list:\t " + thread_list;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_deskscan_manifest_thread_list", e);
		}
		
		return null;
	}
	
	public boolean process_import_manifest_my_module_description(int beginning_offset, String key, String value, String []arr, String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(my_module_description == null)
			{
				my_module_description = new Node_DLL(director);
				
				if(my_module_description.tree_process == null)
					my_module_description.tree_process = new TreeMap<Integer, Node_Process>();
					
				my_module_description.tree_process.put(this.PID, this);
			}
			
			my_module_description.process_import_manifest_token(beginning_offset, key, value, arr, line, lower, mtd_designator, line_num, br, designator_len, multi_lines_used_to_describe_single_node, this);
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_my_module_description", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	//converting to 20 node
		/**
		 * 			if(tree_threads.size() > MAX_TREE_NODE_COUNT)
				{
					int count = 0;				
					pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
					
					for(Node_Threads node : tree_threads.values())
					{															
						if(count % MAX_TREE_NODE_COUNT == 0 && count > 0)
						{
							pw.println("\t\t\t" +  "]},");
							
							pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
						}
						
						node.write_node_information(pw);
						
						++count;
					}
					
					pw.println("\t\t\t" +  "]},");								
				}
		 * 
		 */
			
	
}
