/**
 * Instantiated to execute plugins
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

public class Analysis_Plugin_SUPER_MODULES extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_SUPER_MODULES";
	public static volatile Driver driver = new Driver();
	

	
	public volatile Advanced_Analysis_Director parent = null;
	

	public volatile String lower = "";
	
	public volatile Node_Process process = null;
	
	public volatile TreeMap<String, Node_Driver> tree_module_dump_files_to_rename = new TreeMap<String, Node_Driver>();
	
	


	
	public Analysis_Plugin_SUPER_MODULES(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT)
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

					this.process_plugin_line_moddump(line);
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
										
			//run modules
			parent.plugin_modules = new Analysis_Plugin_modules(null, parent, "modules", "Print list of loaded modules", EXECUTE_VIA_THREAD, jta_output); //run modules and modscan within moddump!
			
			//run modscan
			parent.plugin_modscan = new Analysis_Plugin_modscan(null, parent, "modscan", "Pool scanner for kernel modules", EXECUTE_VIA_THREAD, jta_output); 
			
			//run drivermodule
			parent.plugin_drivermodule = new Analysis_Plugin_drivermodule(null, parent, "drivermodule", "Associate driver objects to kernel modules", EXECUTE_VIA_THREAD, jta_output);
			
			//run driverscan
			parent.plugin_driverscan = new Analysis_Plugin_driverscan(null, parent, "driverscan", "Pool scanner for driver objects", EXECUTE_VIA_THREAD, jta_output);
						
			//run driverirp
			parent.plugin_driverirp = new Analysis_Plugin_driverirp(null, parent, "driverirp", "Driver IRP hook detection", EXECUTE_VIA_THREAD, jta_output);
			
			//run callbacks
			parent.plugin_callbacks  = new Analysis_Plugin_Callbacks(null, parent, "callbacks", "Print system-wide notification routines", EXECUTE_VIA_THREAD, jta_output); 
			
			//run unloaded modules
			parent.plugin_unloaded_modules  = new Analysis_Plugin_Unloaded_Modules(null, parent, "unloadedmodules", "Print list of unloaded modules", EXECUTE_VIA_THREAD, jta_output); 
			
			//run timers
			parent.plugin_timers  = new Analysis_Plugin_Timers(null, parent, "timers", "Print kernel timers and associated module DPCs", EXECUTE_VIA_THREAD, jta_output); 
			
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
//			if(cmd == null)
//			{
//				cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\" " + plugin_name + " --profile=" + PROFILE;
//			}						
//			
//			if(cmd.toLowerCase().contains("dump") && (!cmd.toLowerCase().contains("hashdump") || !cmd.toLowerCase().contains("evtlogs") || cmd.toLowerCase().contains("lsadump")))
//				cmd = cmd + " --dump-dir " + "\"" + fleOutput.getParentFile().getCanonicalPath(); //leave final " off

			if(cmd == null)
			{
				cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\" " + plugin_name + " --profile=" + PROFILE + " --dump-dir " + "\"" + fleOutput.getParentFile().getCanonicalPath(); //leave final " off;
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
		        	

		        	process_plugin_line_moddump(line);
		        	
		        	//log
		        	pw.println(line);
		        }
		        
		        //rename files
		        rename_files(this.tree_module_dump_files_to_rename, fleOutput.getParentFile(), pw);
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
	
	public boolean rename_files(TreeMap<String, Node_Driver> tree, File directory, PrintWriter pw)
	{
		try
		{
			if(tree == null || tree.isEmpty())
				return false;
			
			if(directory == null || !directory.exists())
				return false;
			
			if(!directory.isDirectory())
				directory = directory.getParentFile();
			
			LinkedList<File> list = new LinkedList<File>();
			
			list = driver.getFileListing(directory, true, null, list);
			
			if(list == null || list.isEmpty())
				return false;
			
			String file_name = "", path = "";	
						
			//fleNew = new File(path + process.process_name + "_" + PID + "." + extension);
			
			pw.println("\n\n#################################################################################################################");
			pw.println("# File Details");
			pw.println("#################################################################################################################");
			//pw.println(FileAttributeData.file_output_header);
			for(File fle : list)
			{
				try
				{
					if(fle == null || !fle.exists())
						continue;
					
					file_name = fle.getName();
					
					if(!tree.containsKey(file_name))
						continue;
					
					String extension = null;
					try
					{
						String [] array = file_name.split("\\.");					
						extension = array[array.length -1].trim(); 
					}catch(Exception e){}
					
					
					path = fle.getParentFile().getCanonicalPath().trim();
					
					if(!path.endsWith(File.separator))
						path = path + File.separator;
					
					Node_Driver node = tree.get(file_name);
					
					if(node == null || node.module_name == null)
						continue;
					
					File fleNew = new File(path + node.module_name.trim() + "_" + file_name);
					
					if(fle.renameTo(fleNew))
						node.fle = fleNew;					
					else
						node.fle = fle;
					
					node.fle_attributes = new FileAttributeData(node.fle, null, null);
					node.fle_attributes.set_hash(false);
					node.fle_attributes.extension = extension;
						
					//pw.println(node.fle_attributes.toString("\t"));
					try	{	pw.println(node.fle_attributes.toString("", "\t ", false));	} catch(Exception e){}
				}
				
				catch(Exception e)
				{
					continue;
				}
			}
				
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "rename_files", e);
		}
		
		return false;
	}
	
	/**
	 * process dll list - for moddump
	 * @param line
	 * @return
	 */
	public boolean process_plugin_line_moddump(String line)
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
			
			if(!lower.startsWith("0x"))
				return false;
			
			String module_base = lower.substring(0, lower.indexOf(" ")).trim();					
			String module_name = line.substring(line.indexOf(" ")+1, line.indexOf("  ")).trim();
			String dump_file_name = line.substring(line.lastIndexOf(" ")).trim();
			
			if(dump_file_name == null || dump_file_name.trim().equals("") || module_name == null || module_name.trim().equals(""))
				return false;
			
			Node_Driver node = new Node_Driver(module_base, module_name, dump_file_name);
		
			//store
			tree_module_dump_files_to_rename.put(dump_file_name, node);
			
			parent.tree_DRIVERS.put(module_name.toLowerCase().trim(), node);
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
