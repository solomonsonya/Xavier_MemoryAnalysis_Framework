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

public class Analysis_Plugin_apihooks extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_apihooks";
	public static volatile Driver driver = new Driver();
	
	public volatile Advanced_Analysis_Director parent = null;

	
	public volatile boolean EXECUTE_VIA_THREAD = false;
	
	public volatile LinkedList<String> list_notified_user_of_import_issues = new LinkedList<String>();
		

	public volatile String lower = "";
	
	public volatile Node_Process process = null;
	
	String hook_mode = null;			
	String hook_type = null;
	String process_line = null;
		String pid = null;
		String process_name = null;
		int PID = -1;
	String victim_module_line = null;
		String victim_module_name = null;
		String victim_module_base_address = null;
	String function = null;
	String hook_address = null;
	String hooking_module = null;
	boolean analyzed_first_0x_line = false;
	boolean MZ_present = false;
	boolean trampoline_detected = false;
	
		
	public volatile LinkedList<String> list_dissassembly_0 = new LinkedList<String>();
	public volatile LinkedList<String> list_dissassembly_1 = null;
	public volatile LinkedList<String> list_dissassembly_2 = null;
	public volatile LinkedList<String> list_dissassembly_3 = null;
	
	public volatile LinkedList<String> list_DISSASSEMBLY = list_dissassembly_0;
	
	
	
	public Analysis_Plugin_apihooks(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread)
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
			
			try	{ parent.tree_advanced_analysis_threads.put(this.plugin_name, this);	} catch(Exception e){}
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
			
			//
			//process command output
			//
			LineIterator line_iterator = new LineIterator(brIn);
			String line = "";
			long line_count = 28;
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
		        
		        //store last hook 
		        store_data();
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
									
			//skip if volatility header
			if(lower.startsWith("volatility foundation "))
				return false;
			
			else if(line.startsWith("ERROR "))
				return false;
			
			if(lower.startsWith("#"))
				return false;
			
										
			else if(lower.startsWith("*****"))
				store_data();	
			
			
			if(lower.startsWith("disassembly(0)")) 
			{
				this.list_dissassembly_0 = new LinkedList<String>();
				this.list_DISSASSEMBLY = list_dissassembly_0;
				return false;
			}
			
			else if(lower.startsWith("disassembly(1)")) 
			{
				this.list_dissassembly_1 = new LinkedList<String>();
				this.list_DISSASSEMBLY = list_dissassembly_1;
				return false;
			}
			
			else if(lower.startsWith("disassembly(2)")) 
			{
				this.list_dissassembly_2 = new LinkedList<String>();
				this.list_DISSASSEMBLY = list_dissassembly_2;
				return false;
			}
			
			else if(lower.startsWith("disassembly(3)")) 
			{
				this.list_dissassembly_3 = new LinkedList<String>();
				this.list_DISSASSEMBLY = list_dissassembly_3;
				return false;
			}
			
			//owt, search for MZ header
			else if(lower.startsWith("0x"))			
			{
				if(list_DISSASSEMBLY == null)
				{
					this.list_dissassembly_0 = new LinkedList<String>();
					list_DISSASSEMBLY = this.list_dissassembly_0;
				}
				
				
				this.list_DISSASSEMBLY.add(line);
				
				if(!analyzed_first_0x_line && lower.contains("jmp"))					
					this.trampoline_detected = true;
				
				analyzed_first_0x_line = true;
				
				if(lower.contains("4d 5a "))
					MZ_present = true;		
				
				return true;
			}
			
			
			if(!line.contains(":"))
				return false;
									
						
			String array [] = line.split(":");
			
			if(array == null || array.length < 2)
				return false;				
			
			lower = array[0].toLowerCase().trim();
			
			if(lower.startsWith("hook mode"))
				hook_mode = driver.toString(array, 1);
			
			else if(lower.startsWith("hook type"))
				hook_type = driver.toString(array, 1);
			
			else if(lower.startsWith("process"))
			{
				try
				{
					process_line = driver.toString(array, 1).trim();
					
					pid = process_line.substring(0, process_line.indexOf(" ")).trim();
					process_name = process_line.substring(process_line.indexOf(" ")).replace("(", "").replace(")", "").trim();
					
					PID = Integer.parseInt(pid.trim());										
				}
				catch(Exception e)
				{
					this.error_processing_line(line);
				}							
			}
			
			else if(lower.startsWith("victim module"))
			{
				victim_module_line = driver.toString(array, 1).trim();
												
				victim_module_name = victim_module_line.substring(0, victim_module_line.indexOf(" ")).trim();
				
				victim_module_base_address = victim_module_line.substring(victim_module_line.indexOf("(")+1, victim_module_line.indexOf("-")).trim();
			}
			
			else if(lower.startsWith("function"))
				 this.function = driver.toString(array, 1);
			
			else if(lower.startsWith("hook address"))
				 hook_address = driver.toString(array, 1);
			
			else if(lower.startsWith("hooking module"))
				 hooking_module = driver.toString(array, 1);
			
			
			
				
					
			
			
			return true;
		
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "process_plugin_line", e);
			error_processing_line(line);
		}
		
		return false;
	}
	
	public boolean store_data()
	{
		try
		{
			Node_DLL dll = null;
			Node_Driver kernel_module = null;
			if(this.victim_module_base_address != null)
			{
				LinkedList<Node_DLL> list = parent.tree_DLL_MODULES_linked_by_VAD_base_start_address.get(victim_module_base_address.toLowerCase().trim());
				
				if(list != null)
				{
					if(list.size() == 1)
						dll = list.getFirst();
					
					else
					{
						try
						{
							for(Node_DLL node: list)
							{
								if(dll != null)
									break;
								
								if(node.path.toLowerCase().trim().endsWith(this.victim_module_name.toLowerCase().trim()))
								{
									dll = node;
									break;
								}
							}
						}
						catch(Exception e)
						{
							this.error_processing_line("store_data mtd from list for victim module: " + this.victim_module_line);
						}											
					}
				}
				
				//still dont have the dll, try to search the entire tree
				if(dll == null)
				{
					try
					{
						for(Node_DLL node: parent.tree_DLL_by_path.values())
						{
							if(dll != null)
								break;
							
							if(node.path.toLowerCase().trim().endsWith(this.victim_module_name.toLowerCase().trim()))
							{
								dll = node;
								break;
							}							
						}
					}
					catch(Exception e)
					{
						this.error_processing_line("store_data mtd from tree for victim module: " + this.victim_module_line);
					}
				}
				
				//ensure we finally have the node, otherwise, exit!
				if(dll == null)
				{
					//search drivers if if failed to find a dll
					if(parent.tree_DRIVERS.containsKey(victim_module_name.toLowerCase().trim()))
					{
						kernel_module = parent.tree_DRIVERS.get(victim_module_name.toLowerCase().trim());
						driver.directive("NOTE: APIHOOK detected on kernel module: [" + victim_module_name + "] - refer to APIHOOKS for more details --> " + victim_module_line);
					}
					
					else if(!list_notified_user_of_import_issues.contains(victim_module_line))
					{
						sop("[" + this.plugin_name + "] NOTE! I could not find " + this.victim_module_line + " from DLL list in order to properly annotate the APIHOOK");
						
						list_notified_user_of_import_issues.add(victim_module_line);
					}
					
					
				}
				
				else if(hook_address == null || hook_address.length() < 2)
				{
					if(!list_notified_user_of_import_issues.contains(victim_module_line))
					{
						sop("[" + this.plugin_name + "] * NOTE: I was not able to process API Hook [" + this.victim_module_line + "] - I could not determine hook_address: [" + hook_address + "]");								
						list_notified_user_of_import_issues.add(victim_module_line);
					}
					
				}
				
				//otw, process!
				else
				{									
					//get process
					Node_Process process = parent.tree_PROCESS.get(PID);
					
					//create node
					Node_ApiHook hook = new Node_ApiHook(dll, process, process_name, pid, PID);
					
					//populate entries - SolomoN SonY@ 
					hook.hook_mode = hook_mode;
					hook.hook_type=hook_type;
					hook.process_line=process_line;					
					hook.victim_module_line=victim_module_line;
					hook.victim_module_name=victim_module_name;
					hook.victim_module_base_address=victim_module_base_address;
					hook.function=function;
					hook.hook_address=hook_address;
					hook.hooking_module=hooking_module;
					hook.Trampoline_Initial_JMP_Detected = this.trampoline_detected;
					hook.MZ_Detected = this.MZ_present;
					
					hook.list_dissassembly_0 = this.list_dissassembly_0;
					hook.list_dissassembly_1 = this.list_dissassembly_1;
					hook.list_dissassembly_2 = this.list_dissassembly_2;
					hook.list_dissassembly_3 = this.list_dissassembly_3;
					
					//link
					parent.tree_API_HOOK.put(hook_address, hook);
					dll.tree_api_hook.put(hook_address, hook);
					
					if(process != null)
						process.tree_api_hook.put(hook_address, hook);
					
					if(this.trampoline_detected && !parent.list_API_HOOKS_WITH_HEAD_TRAMPOLINE_PRESENT.contains(dll))
						parent.list_API_HOOKS_WITH_HEAD_TRAMPOLINE_PRESENT.add(dll);
					
					if(this.MZ_present && !parent.list_API_HOOKS_WITH_MZ_PRESENT.contains(dll))
						parent.list_API_HOOKS_WITH_MZ_PRESENT.add(dll);
					
					
					
				}
				
			}
			
			//
			//re-init
			//
			hook_mode = null;			
			hook_type = null;
			process_line = null;
			pid = null;
			process_name = null;
			PID = -1;
			victim_module_line = null;
			victim_module_name = null;
			victim_module_base_address = null;
			function = null;
			hook_address = null;
			hooking_module = null;		
			analyzed_first_0x_line = false;
			MZ_present = false;
			trampoline_detected = false;
			
			LinkedList<String> list_dissassembly_0 = new LinkedList<String>();
			LinkedList<String> list_dissassembly_1 = null;
			LinkedList<String> list_dissassembly_2 = null;
			LinkedList<String> list_dissassembly_3 = null;			
			LinkedList<String> list_DISSASSEMBLY = list_dissassembly_0;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "store_data", e);
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
			if(EXECUTE_VIA_THREAD)
				System.out.println(out);
			else					
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
			if(EXECUTE_VIA_THREAD)
				System.out.print(out);
			else					
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
