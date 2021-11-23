/**
 * Save details in list_header, and Commands in list_cmd
 * 
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import java.io.*;
import java.util.*;
import Driver.*;

public class Node_CmdScan 
{
	public static final String myClassName = "Node_CmdScan";
	public static volatile Driver driver = new Driver();
	
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
	
	
	
	
	
	
	
	
	
}
