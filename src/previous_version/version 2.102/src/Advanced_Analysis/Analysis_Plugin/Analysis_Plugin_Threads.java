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

public class Analysis_Plugin_Threads extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_Threads";
	public static volatile Driver driver = new Driver();
	

	
	public volatile Advanced_Analysis_Director parent = null;
	

	public volatile String lower = "";
	
	public volatile Node_Process process = null;
	public volatile Node_Threads node = null;
	
	public volatile String ethread_address = null;
	public volatile String pid = null;
	public volatile String TID = null;
	
	


	
	public Analysis_Plugin_Threads(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT)
	{
		try
		{
			fle_import = file;
			parent = par;
			plugin_name = PLUGIN_NAME;
			plugin_description = PLUGIN_DESCRIPTION;
			jta_output = jta_OUTPUT;
			
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
			
			if(line.trim().startsWith("#"))
				return false;
			
			
			line = line.replace("	", " ").replace("\t", " ").replace("\\??\\", "").trim();
			
			if(parent.system_drive != null)
				line = line.replace("\\Device\\HarddiskVolume1", parent.system_root).replace("\\SystemRoot", parent.system_root);
			
			if(line.equals(""))
				return false;
			
			lower = line.toLowerCase().trim();
									
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
			
			//sop("threads: " + line);		
			

		String [] array = line.split(" ");	
		String value = line.substring(line.indexOf(":")+1).trim();
		
		if(array == null || array.length < 2)
			return false;
		
		if(array[0].toLowerCase().trim().startsWith("ethread"))
		{
			//re-init
			this.ethread_address = array[1].trim();					
			this.pid = array[3].trim();
			this.TID = array[5].trim();
			
			this.process = parent.tree_PROCESS.get(Integer.parseInt(pid.trim()));
			node = new Node_Threads(ethread_address, pid, TID, process, line);												
		}
		else if(lower.startsWith("tags") && node != null)
			node.tags = value;
		else if(lower.startsWith("created") && node != null)
			node.created = value;
		
		else if(lower.startsWith("exited") && node != null)
			node.exited = value;
		
		else if(lower.startsWith("owning process") && node != null)
			node.owning_process_name = value;
		
		else if(lower.startsWith("attached process") && node != null)
			node.attached_process_name = value;
		
		else if(lower.startsWith("state") && node != null)
			node.state = value;
		
		else if(lower.startsWith("basepriority") && node != null)
			node.base_priority = value;
		
		else if(lower.startsWith("priority") && node != null)
			node.priority = value;
		
		else if(lower.startsWith("teb") && node != null)
			node.TEB = value;
		
		else if(lower.startsWith("startaddress") && node != null)
			node.start_address = value;
		
		else if(lower.startsWith("servicetable") && node != null)
			node.service_table_address = value;
		
		else if(lower.startsWith("[0]") && node != null)
			node.service_table_0 = value;
		
		else if(lower.startsWith("[1]") && node != null)
			node.service_table_1 = value;
		
		else if(lower.startsWith("[2]") && node != null)
			node.service_table_2 = value;
		
		else if(lower.startsWith("[3]") && node != null)
			node.service_table_3 = value;
		
		else if(lower.startsWith("win32thread") && node != null)
			node.win32thread = value;
							
		else if(lower.contains("="))
		{
			for(String entry : array)
			{
				if(entry == null)
					continue;
				
				entry = entry.toLowerCase().trim();
				value = entry.substring(entry.indexOf("=")+1).trim();
				
				if(entry.startsWith("eax"))
					node.eax = value;
				else if(entry.startsWith("ebx"))
					node.ebx = value;
				else if(entry.startsWith("ecx"))
					node.ecx = value;
				else if(entry.startsWith("edx"))
					node.edx = value;
				else if(entry.startsWith("esi"))
					node.esi = value;
				else if(entry.startsWith("edi"))
					node.edi = value;
				else if(entry.startsWith("eip"))
					node.eip = value;
				else if(entry.startsWith("esp"))
					node.esp = value;
				else if(entry.startsWith("ebp"))
					node.ebp = value;
				else if(entry.startsWith("err"))
					node.err = value;
				else if(entry.startsWith("cs"))
					node.cs = value;
				else if(entry.startsWith("ss"))
					node.ss = value;
				else if(entry.startsWith("ds"))
					node.ds = value;
				else if(entry.startsWith("es"))
					node.es = value;
				else if(entry.startsWith("gs"))
					node.gs = value;
				else if(entry.startsWith("fs"))
					node.fs = value;
				else if(entry.startsWith("ef"))
					node.efl = value;
				else if(entry.startsWith("dr0"))
					node.dr0 = value;
				else if(entry.startsWith("dr1"))
					node.dr1 = value;
				else if(entry.startsWith("dr2"))
					node.dr2 = value;
				else if(entry.startsWith("dr3"))
					node.dr3 = value;
				else if(entry.startsWith("dr4"))
					node.dr4 = value;
				else if(entry.startsWith("dr5"))
					node.dr5 = value;
				else if(entry.startsWith("dr6"))
					node.dr6 = value;
				else if(entry.startsWith("dr7"))
					node.dr7 = value;
			}
				
				
		}
		
			/*if(lower == null)
				 = token;
			else if( == null)
				 = token;
			else if( == null)
				 = token;
			else if( == null)
				 = token;
			else if( == null)
				 = token;
			else if( == null)
				 = token;
			else if( == null)
				 = token;
			else if( == null)
				 = token;
			else if( == null)
				 = token;
			else if( == null)
				 = token;	*/	
			
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
