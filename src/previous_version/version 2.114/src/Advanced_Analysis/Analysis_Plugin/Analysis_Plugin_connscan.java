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

public class Analysis_Plugin_connscan extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_connscan";
	public static volatile Driver driver = new Driver();
	
	public volatile Advanced_Analysis_Director parent = null;
	

	public volatile String lower = "";
	
	public volatile Node_Process process = null;
	
	
	public Analysis_Plugin_connscan(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT)
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
			//build cmd
			//
			if(cmd == null)
			{
				cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\" " + plugin_name + " --profile=" + PROFILE;
			}
			else if(cmd.toLowerCase().contains("dump"))//cmd override provided!
			{
				sop("\n\nSOLO, PROCESS OVERRIDE CMD E.G. DUMPFILES\n\n");
			}
			
			
			//
			//notify
			//
			if(parent.DEBUG)
				sop("\n* * * Processing plugin: [" + plugin_name + "]\n");
			else
				sp("\nprocessing plugin: [" + plugin_name + "]...");
								
			
			//split the command now into command and params
			String array [] = cmd.split("\\-f");
			
			String command = array[0].trim();
			String params = "";
			String execution_command = "";
			boolean rename_files = true;
			
			for(int i = 1; array != null && i < array.length; i++)
			{
				params = params + " -f " + array[i].trim();
			}
			
			//
			//NOTIFY
			//
			if(parent.DEBUG)
				sop("[" + plugin_name + "]\t Executing command --> " + command + params);
			
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
			
			File fleOutput_connections = null;
			
			try	
			{	
				if(!fleOutput.getParentFile().exists() || !fleOutput.getParentFile().isDirectory())
				fleOutput.getParentFile().mkdirs();	
			}	 catch(Exception e){}
			
			
			//
			//EXECUTE COMMAND!
			//
			ProcessBuilder process_builder = null;	
			
			
			if(driver.isWindows)
			{
				process_builder = new ProcessBuilder("cmd.exe", "/C",  command +  params);
				execution_command = command +  params;
				
				/*
				 * DUMP FILES
				 * plugin_name.equalsIgnoreCase("procdump") 	||
					plugin_name.equalsIgnoreCase("dlldump") 		||
					plugin_name.equalsIgnoreCase("dumpcerts") 	||
					plugin_name.equalsIgnoreCase("dumpfiles") 	||
					plugin_name.equalsIgnoreCase("dumpregistry") ||
					plugin_name.equalsIgnoreCase("memdump") 		||
					plugin_name.equalsIgnoreCase("moddump")		||
					plugin_name.equalsIgnoreCase("evtlogs")		||
					plugin_name.equalsIgnoreCase("vaddump")		||
					params.contains("--dump-dir")
				 */
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
			long line_count = 0;
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
						
			
				
				if(fleOutput_connections != null && fleOutput_connections.exists())
					driver.sop("It appears I was able to extract specific foreign addresses from this plugin and write them to disk. If successful, connection information file has been written to --> " + fleOutput_connections + "\n");
									
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
			if(line == null)
				return false;
			
			line = line.trim();
			
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
						
			//
			//remove header
			//
			else if(lower.startsWith("offset")) //--> e.g., Offset(P)  Local Address             Remote Address            Pid
				return false;
			
			else if(lower.startsWith("-----")) //--> ---------- ------------------------- ------------------------- ---
				return false;
			
			String array [] = line.split(" ");
			
			if(array == null || array.length < 3)
				return false;				
			
			String offset = null;
			String local_addr = null;
			String remote_addr = null;
			String pid = null;
			
			//0x81acf008 192.168.30.129:1347       54.83.43.69:80            888
			for(String token : array)
			{
				token = token.trim();
				
				if(token.equals(""))
					continue;
				
				if(offset == null)
					offset = token;						
				else if(local_addr == null)
					local_addr = token;
				else if(remote_addr == null)
					remote_addr = token;
				else if(pid == null)
					pid = token;				
			}
						
				//store
			int PID = Integer.parseInt(pid.trim());
			
			if(PID < 0)
				return false;
			
			//get the process
			this.process = parent.tree_PROCESS.get(PID);
			
			if(this.process == null)
			{
				sop("\n\nNOTE: I could not find process PID:[ " + PID + "] that for connection line --> " + line);
				return false;
			}
			
			
			String key = local_addr;
			
			if(process.tree_netstat.containsKey(key))
				return false;
			
			//otw, new entry
			Node_Netstat_Entry netstat_entry = new Node_Netstat_Entry();
			
			netstat_entry.process = this.process;
			
			netstat_entry.offset_connscan = offset;
			netstat_entry.local_address = local_addr;
			netstat_entry.foreign_address = remote_addr;
			netstat_entry.PID = PID;
			
			process.tree_netstat.put(key, netstat_entry);
			
			if(!parent.tree_NETSTAT.containsKey(PID))
				parent.tree_NETSTAT.put(PID, process);
			
			//
			//process whois
			//
			netstat_entry.whois(path_fle_analysis_directory);
			
			
			return true;
		
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "process_plugin_line", e);
			error_processing_line(line);
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
	
	
	
	
	
	
	
	
	
	
	
	
	public boolean STUB_set_command_line_STUB(String line)
	{
		try
		{
			if(line == null)
				return false;
			
			line = line.trim();
			
			if(line.equals(""))
				return false;
				
			String header = "command line";
			
			String lower = line.toLowerCase().trim();
			int index = lower.indexOf(header);
			
			String value = line.substring(index + header.length()).trim();
			
			if(value.startsWith(":"))
				value = value.substring(1).trim();
			
			sop("Command line: " + value);
				
				
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "STUB_set_command_line_STUB", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
}
