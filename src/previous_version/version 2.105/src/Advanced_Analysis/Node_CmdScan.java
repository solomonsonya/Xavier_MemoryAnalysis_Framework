/**
 * Save details in list_header, and Commands in list_cmd
 * 
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import java.io.*;
import java.util.*;
import Driver.*;
import Interface.JTextArea_Solomon;

public class Node_CmdScan 
{
	public static final String myClassName = "Node_CmdScan";
	public static volatile Driver driver = new Driver();
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false;
	
	/**e.g. CommandProcess: conhost.exe Pid: 2260, CommandHistory: 0x38ea90 Application: DumpIt.exe Flags: Allocated, etc*/
	public volatile LinkedList<String> list_cmd_header = new LinkedList<String>();
	/**e.g., Cmd #0 @ 0x1de3c0: St4G3$1, Cmd #15 @ 0x1c0158:, etc*/
	public volatile LinkedList<String> list_cmd_details = new LinkedList<String>();
	
	/**contains specific console entries by execution of this command*/
	public volatile LinkedList<String> list_consoles_output = null;
	
	public volatile Advanced_Analysis_Director director = null;
	
	public volatile Node_Process process = null;
	
	/**e.g. 0x1fe9c0 from line --> CommandHistory: 0x1fe9c0 Application: cmd.exe Flags: Allocated, Reset*/
	public volatile String command_history_id = null;
	
	//
	//pupulated by consoles
	//
	public volatile String ConsoleProcess_line_1 = null;
	public volatile String Console_id_line_2 = null;
	public volatile String HistoryBufferCount_line_3 = null;
	public volatile String OriginalTitle_line_4 = null;
	public volatile String Title_line_5 = null;
	public volatile String AttachedProcess_line_6a = null;
	public volatile String AttachedProcess_line_6b = null;
	public volatile String AttachedProcess_line_6c = null;
	public volatile String AttachedProcess_line_6d = null;
	public volatile String AttachedProcess_line_6e = null;
	public volatile String AttachedProcess_line_6f = null;
	public volatile String AttachedProcess_line_6g = null;	
	public volatile String CommandHistory = null;
	
	public Node_CmdScan(String header_line, Advanced_Analysis_Director parent)
	{
		try
		{
			director = parent;
			process_header(header_line);
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	
	
	
	
	/**
	 * CommandProcess: csrss.exe Pid: 1752
	 * @param header_line
	 * @return
	 */
	public boolean process_header(String header_line)
	{
		try
		{
			if(header_line == null)
				return false;
			
			header_line = header_line.trim();
			
			if(header_line.equals(""))
				return false;
			
			String lower = header_line.toLowerCase().trim();
			
			if(!lower.contains("pid:"))
				return false;
			
			//Split the headerstring
			String [] array = header_line.split(" ");
			
			//iterate, and break when we find the first value to be the PID:
			int PID = -1;
			for(String token : array)
			{
				try
				{
					PID = Integer.parseInt(token.trim());
					break;
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			process = director.tree_PROCESS.get(PID);
			
			if(process == null)
				return false;
			
			//link
			if(process.list_cmd_scan == null)
			{
				process.list_cmd_scan = new LinkedList<Node_CmdScan>();
				
				director.tree_process_to_link_cmdline_cmdscan_consoles.put(process.PID, process);
			}
				
			process.list_cmd_scan.add(this);
			
			if(header_line == null || header_line.toLowerCase().trim().equals("null"))
				return true;
			
			list_cmd_header.add(header_line);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_header", e, true);
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
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(command_history_id, "command_history_id", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(ConsoleProcess_line_1, "ConsoleProcess", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(Console_id_line_2, "Console_id", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(HistoryBufferCount_line_3, "HistoryBufferCount", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(OriginalTitle_line_4, "OriginalTitle", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(Title_line_5, "Title", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(AttachedProcess_line_6a, "AttachedProcess", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(AttachedProcess_line_6b, "AttachedProcess", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(AttachedProcess_line_6c, "AttachedProcess", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(AttachedProcess_line_6d, "AttachedProcess", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(AttachedProcess_line_6e, "AttachedProcess", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(AttachedProcess_line_6f, "AttachedProcess", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(AttachedProcess_line_6g, "AttachedProcess", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(CommandHistory, "CommandHistory", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);

	
			//
			//list_cmd_header
			//
			if(list_cmd_header != null)
			{
				for(String detail : list_cmd_header)
				{
					XREF_SEARCH_HIT_FOUND |= this.check_value(detail, "Command Header", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				}
			}
			
			//
			//list_cmd_details
			//
			if(list_cmd_details != null)
			{
				for(String detail : list_cmd_details)
				{
					XREF_SEARCH_HIT_FOUND |= this.check_value(detail, "Command Details", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				}
			}
			
			//
			//list_consoles_output
			//
			if(list_consoles_output != null)
			{
				for(String detail : list_consoles_output)
				{
					XREF_SEARCH_HIT_FOUND |= this.check_value(detail, "Console Output", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
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
