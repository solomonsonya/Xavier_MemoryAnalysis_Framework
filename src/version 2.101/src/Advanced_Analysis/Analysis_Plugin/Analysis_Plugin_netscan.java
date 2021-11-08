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

public class Analysis_Plugin_netscan extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_sockscan";
	public static volatile Driver driver = new Driver();
	
	public volatile Advanced_Analysis_Director parent = null;
	
	public volatile String lower = "";
	
	public volatile Node_Process process = null;
	
	


	
	public Analysis_Plugin_netscan(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread)
	{
		try
		{
			fle_import = file;
			parent = par;
			plugin_name = PLUGIN_NAME;
			plugin_description = PLUGIN_DESCRIPTION;
			
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
			
			try	{ parent.tree_advanced_analysis_threads.put(plugin_name, this);	} catch(Exception e){}			
			EXECUTION_STARTED = true;
			
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
			
			if(command.toLowerCase().contains("volatility") || params.toLowerCase().contains("volatility"))
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
			
			if(line.trim().startsWith("#"))
				return false;
			
			
			line = line.trim();
			
			if(line.equals(""))
				return false;
			
			lower = line.toLowerCase().trim();
									
			//skip if volatility header
			if(lower.startsWith("volatility foundation "))
				return false;
			else if(line.startsWith("ERROR "))
				return false;
						
			//
			//remove header
			//
			else if(lower.startsWith("offset")) //--> e.g., Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
				return false;
			
			else if(lower.startsWith("----")) //--> ---------- -------- ------ ------ --------------- --------------- -----------
				return false;
			
			//keep value
			if(!line.startsWith("0x"))
				return false;
			
			String array [] = line.split(" ");
			
			if(array == null || array.length < 3)
				return false;				
			
			String offset = null;
			String protocol = null;
			String local_addr = null;
			String foreign_addr = null;
			String state = null;
			String pid = null;
			String owner_name = null;
			String creation_date = null;
			String creation_time = null;
			String creation_utc = null;
			
			
			//Process --> 0x3d734de0         UDPv6    ::1:1900                       *:*                                   2060     svchost.exe    2020-02-13 17:10:41 UTC+0000
			for(String token : array)
			{
				token = token.trim();
				
				if(token.equals(""))
					continue;
				
				else if(offset == null)
					offset = token;
				else if(protocol == null)
					protocol = token;
				else if(local_addr == null)
					local_addr = token;
				else if(foreign_addr == null)
					foreign_addr = token;
				else if(state == null)
				{
					state = token;
					
					//check if state is a value, or blank and that it actually took the PID
					try
					{
						Integer.parseInt(state.trim());
						
						//if it got here, then state was blank, and we actually parsed the PID instead
						pid = token;
						
						state = "";
						
						//owt, state was LISTENING or something like that, continue to process the pid upon next iteration
					}
					catch(Exception e){}					
				}							
				
				else if(pid == null)
					pid = token;
				else if(owner_name == null)
					owner_name = token;
				else if(!token.contains("-") && !token.contains(":") && !token.contains("+"))
					owner_name = owner_name + " " + token;
				else if(creation_date == null)
					creation_date = token;
				else if(creation_time == null)
					creation_time = token;
				else if(creation_utc == null)
					creation_utc = token;
				
				/*else if( == null)
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
					 = token;*/
				
				
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
			
			Node_Netstat_Entry netstat_entry = new Node_Netstat_Entry();
			
			if(netstat_entry.process == null)
				netstat_entry.process = this.process;
			else if(netstat_entry.process.PID != PID)
			{
				sop("\n\nNOTE: PID mismatch in " + this.plugin_name + " for line [" + line + "]. This entry was previously loaded for PID: [" + netstat_entry.process.PID + "");
			}
			
			netstat_entry.offset_netscan = offset;
			
			if(netstat_entry.PID < 0)
				netstat_entry.PID = PID;
			
			if(netstat_entry.local_address == null)
				netstat_entry.local_address = local_addr;
			
			if(netstat_entry.protocol == null)
				netstat_entry.protocol = protocol;
			
			if(netstat_entry.local_address == null)
				netstat_entry.local_address = local_addr;
			
			if(netstat_entry.foreign_address == null)
				netstat_entry.foreign_address = foreign_addr;
			
			if(netstat_entry.state == null)
				netstat_entry.state = state;
			
			if(netstat_entry.owner_name == null)
				netstat_entry.owner_name = owner_name;
			
			if(netstat_entry.creation_date == null)
				netstat_entry.creation_date = creation_date;
			
			if(netstat_entry.creation_time == null)
				netstat_entry.creation_time = creation_time;
			
			if(netstat_entry.creation_utc == null)
				netstat_entry.creation_utc = creation_utc;		
			
			//check to update process name with owner name if needed!
			if(netstat_entry.owner_name != null && !netstat_entry.owner_name.trim().equals("") && (netstat_entry.process.process_name == null || netstat_entry.process.process_name.trim().equals("")))
			{
				sop("\nNOTE: From [" + plugin_name + "] I am setting process name to [" + netstat_entry.owner_name + "] as it was missing previously for PID[" + PID + "] by line -->" + line);
				netstat_entry.process.process_name = netstat_entry.owner_name; 
			}
					
			
			//
			//tree linking
			//			
			if(!process.tree_netstat.containsKey(key))
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
	
	
	
	
	
	
	
	public boolean sop(String out)
	{
		try
		{
			Interface.jpnlAdvancedAnalysisConsole.append(out);						
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	public boolean sp(String out)
	{
		try
		{
			Interface.jpnlAdvancedAnalysisConsole.append_sp(out);						
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
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
