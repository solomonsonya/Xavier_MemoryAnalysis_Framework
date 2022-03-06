/**
 * Consoles - find consoles output and add it to respective process node
 * 
 * Instantiated to execute plugin without any special processing
 * @author Solomon Sonya
 */
package Advanced_Analysis.Analysis_Plugin;

import Advanced_Analysis.*;
import Driver.*;
import Interface.*;
import Plugin.*;
import Worker.*;
import javafx.stage.DirectoryChooser;

import java.awt.event.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.LinkedList;
import java.util.TreeMap;

import org.apache.commons.io.LineIterator;

public class Analysis_Plugin_consoles extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_consoles";
	public static volatile Driver driver = new Driver();
	
	
	
	public volatile Advanced_Analysis_Director parent = null;
	

	public volatile String lower = "";
	
	public volatile Node_Process process = null;
	
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
	public volatile String command_history_id = null;
	
	public volatile Node_CmdScan nde_cmd_scan = null;
	
	
	public Analysis_Plugin_consoles(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT)
	{
		try
		{
			fle_import = file;
			parent = par;
			plugin_name = PLUGIN_NAME;
			plugin_description = PLUGIN_DESCRIPTION;
			jta_console_output_execution_status = jta_OUTPUT;
			
			EXECUTION_TIME_STAMP = parent.EXECUTION_TIME_STAMP;
			fle_volatility = parent.fle_volatility;
			fle_memory_image = parent.fle_memory_image;
			PROFILE = parent.PROFILE;
			path_fle_analysis_directory = parent.path_fle_analysis_directory;
			file_attr_volatility = parent.file_attr_volatility;
			file_attr_memory_image = parent.file_attr_memory_image;
			investigator_name = parent.investigator_name;
			investigation_description = parent.investigation_description;
			EXECUTE_VIA_THREAD = execute_via_thread;
			
			if(execute_via_thread)
				this.start();
			else
				commence_action();
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	public void run()
	{
		try
		{
			commence_action();			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean commence_action()
	{
		try
		{

			///////////////////////////////////////////////////////////////////////////////////
			// IMPORT FILE
			//////////////////////////////////////////////////////////////////////////////////
			if(this.fle_import != null && this.fle_import.isFile() && this.fle_import.exists())
			{
				int line_num = 0;
				
				BufferedReader br = new BufferedReader(new FileReader(fle_import));
				
				Start.intface.sp("commencing import on file: " + fle_import.getName());
				
				String line = "";
				while((line = br.readLine()) != null)
				{
					if((line_num++) % 20 == 0)
						Start.intface.sp(".");
					
					if(line_num% Advanced_Analysis_Director.new_line_separator_count == 0)
						Start.intface.sp("\n");

					this.process_plugin_line(line);
				}
				
				try	{	br.close();} catch(Exception e){}
				
				Start.intface.sop(Advanced_Analysis_Director.import_complete_separator + "import complete on " + fle_import.getName());
				
				try	{ parent.tree_advanced_analysis_threads.put(this.plugin_name, this);	} catch(Exception e){}
				EXECUTION_STARTED = true;
				this.EXECUTION_COMPLETE = true;
				
				return true;
			}
			
			
			//////////////////////////////////////////////////////////////////////////////////////
			// EXECUTE PLUGIN CMD
			//////////////////////////////////////////////////////////////////////////////////////
			
			try	{ parent.tree_advanced_analysis_threads.put(this.plugin_name, this);	} catch(Exception e){}			EXECUTION_STARTED = true;

			
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.add(this.plugin_name);	} catch(Exception e){}

			
			boolean status = false;
			
			status = execute_plugin(plugin_name, plugin_description, null, "");			
					
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.remove(this.plugin_name);	} catch(Exception e){}
			
			this.EXECUTION_COMPLETE = true;

			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
		
		try	{	Advanced_Analysis_Director.list_plugins_in_execution.remove(this.plugin_name);	} catch(Exception e){}
		
		this.EXECUTION_COMPLETE = true;

		return false;
	}
	
	
	public boolean execute_plugin(String plugin_name, String plugin_description, String cmd, String additional_file_name_detail)
	{
		try
		{							
			if(fle_volatility == null || !fle_volatility.exists() || !fle_volatility.isFile())
			{
				driver.sop("* * ERROR! Valid volatility executable binary has not been set. I cannot proceed with execution of plugin: [" + plugin_name + "]. * * ");
				return false;
			}
			
			if(fle_memory_image == null || !fle_memory_image.exists() || !fle_memory_image.isFile())
			{
				driver.sop("* * ERROR! Valid memory image for analysis has not been set. I cannot proceed with execution of plugin: [" + plugin_name + "]. * *");				
				return false;
			}
			
			//
			//INITIALIZE OUTPUT DIRECTORY
			//
			String time_stamp = driver.get_time_stamp("_");

			if(Advanced_Analysis_Director.DO_NOT_INCLUDE_TIME_STAMP_IN_FILE_NAME)
			{
				if(additional_file_name_detail == null || additional_file_name_detail.trim().equals(""))
					fleOutput = new File(path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + ".txt");
				else
					fleOutput = new File(path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + "_" + additional_file_name_detail + "" + ".txt");
			}
			else
				fleOutput = new File(path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + "_" + additional_file_name_detail + time_stamp + ".txt");
			
			try	
			{	
				if(!fleOutput.getParentFile().exists() || !fleOutput.getParentFile().isDirectory())
				fleOutput.getParentFile().mkdirs();	
			}	 catch(Exception e){}
			
			
			//
			//build cmd
			//
			if(cmd == null)
			{
				cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\" " + plugin_name + " --profile=" + PROFILE;
			}						
			
			if((plugin_name.toLowerCase().contains("dump") || plugin_name.toLowerCase().contains("evtlogs")) && !(plugin_name.toLowerCase().contains("hashdump") || plugin_name.toLowerCase().contains("lsadump")))
			{
				//return here and specify which plugins require dumpdir from the class instantiation
				cmd = cmd + " --dump-dir " + "\"" + fleOutput.getParentFile().getCanonicalPath(); //leave final " off
			}
			//+ " --dump-dir \"" + fle_dump_directory.getCanonicalPath();
			
			//
			//notify
			//
			if(parent.DEBUG)
				sop("\n* * * Processing plugin: [" + plugin_name + "]\n");
			else
				sp("\nprocessing plugin: [" + plugin_name + "]...");
								
			
			//split the command now into command and params
			String array [] = cmd.split("\\-f");
			
			String command = cmd;
			String params = "";
			String execution_command = "";
			
			
									
			execution_command = command + params;
			
			//
			//NOTIFY
			//
			if(parent.DEBUG)
				sop("[" + plugin_name + "]\t Executing command --> " + execution_command);
									
			//
			//EXECUTE COMMAND!
			//
			ProcessBuilder process_builder = null;	
			
			
			if(driver.isWindows)
			{
				process_builder = new ProcessBuilder("cmd.exe", "/C",  command +  params);
				execution_command = command +  params;								
			}
							
			//else if(driver.isLinux)
			else
			{
				process_builder = new ProcessBuilder("/bin/bash", "-c",  command +  params);
				
				execution_command = command +  params;
			}
			
			//
			//redirect error stream
			//
			process_builder.redirectErrorStream(true); 
						
			//
			//instantiate new process
			//
			Process process = process_builder.start();
						
			//
			//process input
			//
			PrintWriter pw = new PrintWriter(new FileWriter(fleOutput), true);
			
			if(command.toLowerCase().contains("volatility") || params.toLowerCase().contains("volatility"))
				write_process_header(pw, plugin_name, plugin_description, execution_command);
			
			BufferedReader brIn = new BufferedReader(new InputStreamReader(process.getInputStream()));
			long line_count = 31;
			//
			//process command output
			//
			LineIterator line_iterator = new LineIterator(brIn);
			String line = "";
		    try 
		    {
		        while (line_iterator.hasNext()) 
		        {		        	
		        	line = line_iterator.nextLine();
		        	
		        	if(line == null)
		        		continue;

		        	sp(".");
		        	
		        	if((++line_count) % 100 == 0)
		        		sp("\n");
		        	

		        	process_plugin_line(line);
		        	
		        	//log
		        	pw.println(line);
		        }		       	       		       		        	                		        		      
		    }
		    catch(Exception e)
		    {
		    	driver.sop("check plugin process execution " + plugin_name + " - " + cmd);
		    }
		        
		      
		   //clean up
		    try	{ 	brIn.close();       		}	catch(Exception e){}
		    try	{	process.destroy();			}	catch(Exception e){}
		    try	{ 	line_iterator.close();      }	catch(Exception e){}
		    
		    try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			
			
			//
			//NOTIFY
			//
			//sop("\n\nExecution complete. If successful, output file has been written to --> " + fleOutput + "\n");
			sop("\n" + this.plugin_name + " execution complete.");		
											
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_plugin", e);
		}
		
		return false;
	}
	
	/**
	 * process dll list
	 * @param line
	 * @return
	 */
	public boolean process_plugin_line(String line)
	{
		try
		{			
			///////////////////////////////////////////////////////////////
			//
			// Solo, be sure to enable process_plugin_line!
			//
			/////////////////////////////////////////////////////////////
			
			if(line == null)
				return false;
			
			line = line.replace("	", " ").replace("\t", " ").replace("\\??\\", "");
			
			if(parent.system_drive != null)
				line = line.replace("\\Device\\HarddiskVolume1", parent.system_root).replace("\\SystemRoot", parent.system_root);
			
			if(line.equals(""))
				return false;
			
			lower = line.toLowerCase().trim();
			
			if(lower.startsWith("#"))
				return false;
			
									
			//skip if volatility header
			if(lower.startsWith("volatility foundation "))
				return false;
			else if(line.startsWith("ERROR "))
				return false;
			
			if(lower.startsWith("***"))
				return false;
			
			if(lower.startsWith("----"))
				return false;
									
			//
			//remove errors
			//
			if(lower.startsWith("unable to read "))  //--> e.g., Unable to read PEB for task.
				return false;
			
			//process pid - Line 1
			if(lower.startsWith("consoleprocess:") && lower.contains("pid:"))
			{
				String arr [] = lower.split(" ");
				
				if(arr == null || arr.length < 1)
					return false;
				
				try
				{
					int PID = Integer.parseInt(arr[arr.length-1]);
					this.process = parent.tree_PROCESS.get(PID);

					//re-init
					ConsoleProcess_line_1 = line;
					
					Console_id_line_2 = null;
					HistoryBufferCount_line_3 = null;
					OriginalTitle_line_4 = null;
					Title_line_5 = null;
					AttachedProcess_line_6a = null;
					AttachedProcess_line_6b = null;
					AttachedProcess_line_6c = null;
					AttachedProcess_line_6d = null;
					AttachedProcess_line_6e = null;
					AttachedProcess_line_6f = null;
					AttachedProcess_line_6g = null;
					CommandHistory = null;
					command_history_id = null;
					nde_cmd_scan = null;
					
				}
				catch(Exception e)
				{
					return false;
				}
			}
			
			//process console
			else if(lower.startsWith("console:"))
			{
				Console_id_line_2 = line;
			}
			
			//process HistoryBufferCount
			else if(lower.startsWith("historybuffercount:"))
			{
				HistoryBufferCount_line_3 = line;
			}
			
			//process OriginalTitle
			else if(lower.startsWith("originaltitle:"))
			{
				OriginalTitle_line_4 = line;
			}
			
			//process Title
			else if(lower.startsWith("title:"))
			{
				Title_line_5 = line;
			}
			
			//process AttachedProcess
			else if(lower.startsWith("attachedProcess:"))
			{
				if(AttachedProcess_line_6a == null)
					AttachedProcess_line_6a = line;
				else if(AttachedProcess_line_6b == null)
					AttachedProcess_line_6b = line;
				else if(AttachedProcess_line_6c == null)
					AttachedProcess_line_6c = line;
				else if(AttachedProcess_line_6d == null)
					AttachedProcess_line_6d = line;
				else if(AttachedProcess_line_6e == null)
					AttachedProcess_line_6e = line;
				else if(AttachedProcess_line_6f == null)
					AttachedProcess_line_6f = line;
				else if(AttachedProcess_line_6g == null)
					AttachedProcess_line_6g = line;
				else
				{
					driver.directive("Not storing additional attached Process in " + myClassName + " on line --> " + line);
				}
			}
			
			//process CommandHistory
			else if(lower.startsWith("commandhistory:"))
			{
				CommandHistory = line;
				
				//search for specific command history
				String arr [] = line.trim().split(" ");
				
				command_history_id = arr[1].trim();
				
				//retrieve cmd_scan
				try
				{
					nde_cmd_scan = process.tree_cmdscan_consoles.get(command_history_id);
					
					if(nde_cmd_scan == null)
						throw new Exception("Node did not exist");
				}
				catch(Exception e)
				{
					driver.directive(process.get_process_html_header() + " did not have command history [" + command_history_id + "] I am instantiating now...");
					
					this.nde_cmd_scan = new Node_CmdScan(ConsoleProcess_line_1, parent);
					
					//process header
					if(process.tree_cmdscan_consoles == null)
						process.tree_cmdscan_consoles = new TreeMap<String, Node_CmdScan>();
					
					//link specific history
					process.tree_cmdscan_consoles.put(command_history_id, nde_cmd_scan);										
				}
				
				//store header info
				nde_cmd_scan.ConsoleProcess_line_1 = ConsoleProcess_line_1;
				nde_cmd_scan.Console_id_line_2 = Console_id_line_2;
				nde_cmd_scan.HistoryBufferCount_line_3 = HistoryBufferCount_line_3;
				nde_cmd_scan.OriginalTitle_line_4 = OriginalTitle_line_4;
				nde_cmd_scan.Title_line_5 = Title_line_5;
				nde_cmd_scan.AttachedProcess_line_6a = AttachedProcess_line_6a;
				nde_cmd_scan.AttachedProcess_line_6b = AttachedProcess_line_6b;
				nde_cmd_scan.AttachedProcess_line_6c = AttachedProcess_line_6c;
				nde_cmd_scan.AttachedProcess_line_6d = AttachedProcess_line_6d;
				nde_cmd_scan.AttachedProcess_line_6e = AttachedProcess_line_6e;
				nde_cmd_scan.AttachedProcess_line_6f = AttachedProcess_line_6f;
				nde_cmd_scan.AttachedProcess_line_6g = AttachedProcess_line_6g;
				nde_cmd_scan.CommandHistory = CommandHistory;
				nde_cmd_scan.command_history_id = command_history_id;
				
				//enrich header
				if(!nde_cmd_scan.list_cmd_header.contains(ConsoleProcess_line_1)) nde_cmd_scan.list_cmd_header.add(ConsoleProcess_line_1);
				if(!nde_cmd_scan.list_cmd_header.contains(Console_id_line_2)) nde_cmd_scan.list_cmd_header.add(Console_id_line_2);
				if(!nde_cmd_scan.list_cmd_header.contains(HistoryBufferCount_line_3)) nde_cmd_scan.list_cmd_header.add(HistoryBufferCount_line_3);
				if(!nde_cmd_scan.list_cmd_header.contains(OriginalTitle_line_4)) nde_cmd_scan.list_cmd_header.add(OriginalTitle_line_4);
				if(!nde_cmd_scan.list_cmd_header.contains(Title_line_5)) nde_cmd_scan.list_cmd_header.add(Title_line_5);
				if(!nde_cmd_scan.list_cmd_header.contains(AttachedProcess_line_6a)) nde_cmd_scan.list_cmd_header.add(AttachedProcess_line_6a);
				if(!nde_cmd_scan.list_cmd_header.contains(AttachedProcess_line_6b)) nde_cmd_scan.list_cmd_header.add(AttachedProcess_line_6b);
				if(!nde_cmd_scan.list_cmd_header.contains(AttachedProcess_line_6c)) nde_cmd_scan.list_cmd_header.add(AttachedProcess_line_6c);
				if(!nde_cmd_scan.list_cmd_header.contains(AttachedProcess_line_6d)) nde_cmd_scan.list_cmd_header.add(AttachedProcess_line_6d);
				if(!nde_cmd_scan.list_cmd_header.contains(AttachedProcess_line_6e)) nde_cmd_scan.list_cmd_header.add(AttachedProcess_line_6e);
				if(!nde_cmd_scan.list_cmd_header.contains(AttachedProcess_line_6f)) nde_cmd_scan.list_cmd_header.add(AttachedProcess_line_6f);
				if(!nde_cmd_scan.list_cmd_header.contains(AttachedProcess_line_6g)) nde_cmd_scan.list_cmd_header.add(AttachedProcess_line_6g);
				if(!nde_cmd_scan.list_cmd_header.contains(CommandHistory)) nde_cmd_scan.list_cmd_header.add(CommandHistory);
				

			}
			
			//commandcount
			else if(lower.startsWith("commandcount:") && nde_cmd_scan != null && !nde_cmd_scan.list_cmd_header.contains(line))
				nde_cmd_scan.list_cmd_header.add(line);
			
			//first command
			else if(lower.startsWith("firstcommand:") && nde_cmd_scan != null && !nde_cmd_scan.list_cmd_header.contains(line))
				nde_cmd_scan.list_cmd_header.add(line);
			
			//processhandle
			else if(lower.startsWith("processhandle:") && nde_cmd_scan != null && !nde_cmd_scan.list_cmd_header.contains(line))
				nde_cmd_scan.list_cmd_header.add(line);
			
			//cmd
			else if(lower.startsWith("cmd #") && nde_cmd_scan != null && !nde_cmd_scan.list_cmd_details.contains(line) && !nde_cmd_scan.list_cmd_details.contains(line.replaceFirst(" at ", " @ ")))
				nde_cmd_scan.list_cmd_details.add(line);
			
			//
			//ELSE, ADD THE CONSOLE!
			//
			else if(nde_cmd_scan != null && !lower.startsWith("commandcount:") && !lower.startsWith("firstcommand:") && !lower.startsWith("processhandle:") && !lower.startsWith("cmd #"))
			{
				 if(nde_cmd_scan.list_consoles_output == null)
					nde_cmd_scan.list_consoles_output = new LinkedList<String>();
				
				nde_cmd_scan.list_consoles_output.add(line);
			}
			
			return true;
		
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_plugin_line", e, false);
		}
		
		return false;
	}
	
	
	
	
	
	public boolean error_processing_line(String line)
	{
		try
		{
			sop("plugin: [" + this.plugin_name + "] I was unable to process line -->" + line);
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "error_processing_line", e);
		}
		
		return false;
	}
	
	
	
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	
	
	
	
	
	
	
	
		
	
	
	
	
	
	
	
	
	
}
