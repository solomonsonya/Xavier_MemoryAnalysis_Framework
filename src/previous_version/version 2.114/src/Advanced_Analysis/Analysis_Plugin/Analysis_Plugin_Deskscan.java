/**
 * Instantiated to execute plugin without any special processing
 * @author Solomon Sonya
 */
package Advanced_Analysis.Analysis_Plugin;

import Advanced_Analysis.*;
import Driver.*;
import Interface.*;
import Plugin.*;
import Worker.*;
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

public class Analysis_Plugin_Deskscan extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_Deskscan";
	public static volatile Driver driver = new Driver();
	

	
	public volatile Advanced_Analysis_Director parent = null;
	

	public volatile String lower = "";		
	public volatile Node_Generic desktop = null;
	
	
	public Analysis_Plugin_Deskscan(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT)
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
			
			status = execute_plugin(plugin_name, plugin_description, null, "", true);			
					
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
	
	
	public boolean execute_plugin(String plugin_name, String plugin_description, String cmd, String additional_file_name_detail, boolean include_plugin_header)
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
			
//			if((cmd.toLowerCase().contains("dump") || cmd.toLowerCase().contains("evtlogs")) && (!cmd.toLowerCase().contains("hashdump") || cmd.toLowerCase().contains("lsadump")))
//				cmd = cmd + " --dump-dir " + "\"" + fleOutput.getParentFile().getCanonicalPath(); //leave final " off
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
			
			if(include_plugin_header)
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
			
			line = line.replace("	", " ").replace("\t", " ").replace("\\??\\", "").trim();
			
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
			
			if(lower.startsWith("------"))
				return false;
			
			//
			//remove errors
			//
			if(lower.startsWith("unable to read "))  //--> e.g., Unable to read PEB for task.
				return false;
			
			if(lower.startsWith("desktop:"))
			{
				String [] array = line.split(",");
				
				
				String desk_address = array[0].trim().substring(array[0].indexOf(":")+1).trim();
				String name = array[1].trim().substring(array[1].indexOf(":")+1).trim();
				String next = array[2].trim().substring(array[2].indexOf(":")+1).trim();
				
				if(desk_address == null || desk_address.length() < 3)
					return false;
				
				desktop = null;
				
				if(parent.tree_DESKSCAN != null && parent.tree_DESKSCAN.containsKey(desk_address))
					desktop = parent.tree_DESKSCAN.get(desk_address);
												
				if(desktop == null)
				{
					this.desktop = new Node_Generic(this.plugin_name);					
					parent.tree_DESKSCAN.put(desk_address, desktop);
				}
				
				if(desktop.desktop_offset == null)
					desktop.desktop_offset = desk_address;
				
				if(desktop.name == null)
					desktop.name = name;
				
				if(desktop.next == null)
					desktop.next = next;				
			}
			
			else if(lower.startsWith("sessionid:"))
			{
				String [] array = line.split(",");
				
				
				String session_id = array[0].trim().substring(array[0].indexOf(":")+1).trim();
				String desktop_info = array[1].trim().substring(array[1].indexOf(":")+1).trim();
				String fshooks = array[2].trim().substring(array[2].indexOf(":")+1).trim();
				
				if(session_id == null || session_id.trim().equals(""))
					return false;
				
				if(desktop.session_id == null)
					desktop.session_id = session_id;
				if(desktop.desktop_info == null)
					desktop.desktop_info = desktop_info;
				if(desktop.fshooks == null)
					desktop.fshooks = fshooks;							
			}
			
			else if(lower.startsWith("spwnd:"))
			{
				String [] array = line.split(",");
				
				
				String spwnd = array[0].trim().substring(array[0].indexOf(":")+1).trim();
				String windows = array[1].trim().substring(array[1].indexOf(":")+1).trim();
				
				if(spwnd == null || spwnd.length() < 3)
					return false;
				
				if(desktop.spwnd == null)
					desktop.spwnd = spwnd;
				if(desktop.windows == null)
					desktop.windows = windows;							
			}
			
			else if(lower.startsWith("heap:"))
			{
				String [] array = line.split(",");
				
				
				String heap = array[0].trim().substring(array[0].indexOf(":")+1).trim();
				String size = array[1].trim().substring(array[1].indexOf(":")+1).trim();
				String base = array[2].trim().substring(array[2].indexOf(":")+1).trim();
				String limit = array[3].trim().substring(array[3].indexOf(":")+1).trim();
				
				if(heap == null || heap.length() < 3)
					return false;
				
				if(desktop.heap == null)
					desktop.heap = heap;
				if(desktop.size == null)
					desktop.size = size;
				if(desktop.base == null)
					desktop.base = base;
				if(desktop.limit == null)
					desktop.limit = limit;
			}
			else if(line.contains("("))
			{
				int thread = -1;
				int PID = -1;
				
				String [] array = line.split(" ");
				
				for(String value : array)
				{
					try
					{
						value = value.trim();
						
						if(value.equals(""))
							continue;
						
						if(thread < 0)
							thread = Integer.parseInt(value.trim());
						
						else if(PID < 0)
							PID = Integer.parseInt(value.trim());
						
						else if(thread > -1 && PID > -1)
							break;
						
					}
					catch(Exception e)
					{
						continue;
					}
				}
				
				//break if we don't have heap and pid
				if(thread < 0 || PID < 0)
					return false;
				
				Node_Process process = null;
				
				//retrieve process
				if(parent.tree_PROCESS.containsKey(PID))
					process = parent.tree_PROCESS.get(PID);
				
				if(process == null)
					return false;
				
				//store the process
				if(desktop.tree_process == null)
					desktop.tree_process = new TreeMap<Integer, Node_Process>();
				
				desktop.tree_process.put(PID, process);
				
				//store entry in process
				if(process.tree_deskscan == null)
					process.tree_deskscan = new TreeMap<String, TreeMap<String, Node_Generic>>();
					
				TreeMap<String, Node_Generic> tree = null;
				
				if(process.tree_deskscan.containsKey(desktop.desktop_offset))
					tree = process.tree_deskscan.get(desktop.desktop_offset);
				
				if(tree == null)
				{
					tree = new TreeMap<String, Node_Generic>();
					process.tree_deskscan.put(desktop.desktop_offset, tree);
				}
				
				tree.put(""+thread, desktop);
			}
			
			
			return true;
		
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_plugin_line", e);
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
