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
import java.io.*;
import java.util.LinkedList;
import java.util.TreeMap;

import org.apache.commons.io.LineIterator;

public class Analysis_Plugin_vadtree extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_vadtree";
	public static volatile Driver driver = new Driver();
	
	public static volatile boolean use_system_out_println_for_output = true;
	public volatile boolean EXECUTE_VIA_THREAD = false;
	
	public volatile Advanced_Analysis_Director parent = null;
	

	public volatile String lower = "";
	
	public volatile Node_Process nde_process = null;
	
	


	
	public Analysis_Plugin_vadtree(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread)
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
			
			try	{ parent.tree_advanced_analysis_threads.put(this.plugin_name, this);	} catch(Exception e){}			EXECUTION_STARTED = true;

			
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.add(this.plugin_name);	} catch(Exception e){}

			
			boolean status = false;
			
			status = execute_plugin(plugin_name, plugin_description, null, "");	
			
			//create tree
			create_vad_walk_dot_file();
					
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
		        	

		        	//process_plugin_line(line);
		        	
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
			
			//sop(line);	
			
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
	
	
	
	
	
	
	
	public boolean sop(String out)
	{
		try
		{
			if(use_system_out_println_for_output && EXECUTE_VIA_THREAD)
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
			if(use_system_out_println_for_output && EXECUTE_VIA_THREAD)
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
	
	
	/**
	 * create dot file now, and then use a utility like graphviz to view it
	 * on linux machine, convert dot file to png or jpg via
	 * dot -Tpng infected.dot -o infected.png
	 * dot -Tjpg infected.dot > processes.jpg
	 * 
	 * Green = stacks, yellow=mapped files, gra = dlls, red = heaps
	 * @return
	 */
	public boolean create_vad_walk_dot_file()
	{
		try
		{
			String image_extension = "png";
			
			String time_stamp = driver.get_time_stamp("_");
			String path_dot_file = path_fle_analysis_directory + this.plugin_name + File.separator + "_" + plugin_name + "_" + this.fle_memory_image.getName() + ".dot";
			path_dot_file = path_dot_file.substring(path_dot_file.indexOf(Driver.NAME_LOWERCASE)).trim();
			
			if(!path_dot_file.startsWith(File.separator))
				path_dot_file = File.separator + path_dot_file;
			
			if(!path_dot_file.endsWith(".dot"))
				path_dot_file = path_dot_file + ".dot";
			
			
			
											
			String relative_path_to_converted_dot_process_image = plugin_name + File.separator + "_" + plugin_name + "_" + this.fle_memory_image.getName() + "." + image_extension; 
			
			String cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\"" + " -f " + "\"" + fle_memory_image.getCanonicalPath().trim() + "\"" + " --profile=" + PROFILE + " " + plugin_name + " --output=dot --output-file=\"." + path_dot_file.trim().replace(File.separator,"/");
			
			
			
			//
			//NOTIFY
			//
			if(parent.DEBUG)
				sop("[" + plugin_name + " - dot file]\t Executing command --> " + cmd);
			
			//
			//EXECUTE COMMAND!
			//
			ProcessBuilder process_builder = null;				
			
			if(driver.isWindows)
				process_builder = new ProcessBuilder("cmd.exe", "/C",  cmd);
							
			else//(driver.isLinux)
				process_builder = new ProcessBuilder("/bin/bash", "-c",  cmd);
			
			//
			//redirect error stream
			//
			process_builder.redirectErrorStream(true); 
						
			//
			//instantiate new process
			//
			Process process = process_builder.start();
						
					      
			BufferedReader brIn = new BufferedReader(new InputStreamReader(process.getInputStream()));
			
			//
			//process command output
			//
			LineIterator line_iterator = new LineIterator(brIn);
			String line = "";
			String lower = "";
		    try 
		    {
		        while (line_iterator.hasNext()) 
		        {		        	
		        	line = line_iterator.nextLine();
		        	
		        	if(line == null)
		        		continue;
		        	
		        	lower = line.toLowerCase().trim();

		        
		        }
	        	        		        		        	                		        		      
		    }
		    catch(Exception e)
		    {
		    	driver.sop("check plugin process execution " + "" + plugin_name + " dot" + " - " + cmd);
		    }
		     		    		      
		   //clean up
		    try	{ 	brIn.close();       		}	catch(Exception e){}
		    try	{	process.destroy();			}	catch(Exception e){}
		    try	{ 	line_iterator.close();      }	catch(Exception e){}
		   
		    
		    //
		    //Analyze dot file for each process
		    //
		    
		  File fle_vad_tree_dot = new File("." + File.separator + path_dot_file);
		  
		 BufferedReader br = new BufferedReader(new FileReader(fle_vad_tree_dot));
		 line = "";
							 		 
		 String pid = "";
		 
		 File fle_data = null;
		 File fle_image = null;
		 PrintWriter pw = null;
		 
		 while((line = br.readLine()) != null)
		 {
			 lower = line.toLowerCase().trim();
			 
			 
			 if(lower.startsWith("/*************"))
				 continue;
			 
			 //beginning of fle
			 else if(lower.contains("pid: "))
			 {
				 pid = line.substring(line.indexOf(":")+1, line.lastIndexOf(" ")).trim();
				 
				 fle_data = new File(path_fle_analysis_directory + plugin_name + File.separator + "vadtree_output_data" + File.separator + "vadtree_" + pid + "_" + this.fle_memory_image.getName() + ".dot");				 
				 try	{	fle_data.getParentFile().mkdirs();	} catch(Exception e){}
				 				 				 
				 try
				 {
					 nde_process = parent.tree_PROCESS.get(Integer.parseInt(pid.trim()));
				 }
				 catch(Exception e){}
												 
				 //crete new pw
				 pw = new PrintWriter(new FileWriter(fle_data));
				 
				 //write first entry
				 pw.println(line);
						 
			 }
			 
			 //end of file
			 else if(lower.equals("}"))
			 {
				 if(pw != null)
				 {
					 pw.println(line);
					 
					 //close prev file
					 try	{	pw.flush();	} catch(Exception e){}
					 try	{	pw.close();	} catch(Exception e){}
					 
					 //
					 //link
					 //
					 
					 try
					 {
						 //nde_process = parent.tree_PROCESS.get(pid);
						 
						 if(this.nde_process != null)
						 {
							 nde_process.fle_vadtree_output_data = fle_data;							 
						 }
					 }
					 catch(Exception e){}					 					 
					 
					 //
					 //create png image
					 //
					 try
					 {
						 fle_image = new File(path_fle_analysis_directory + plugin_name + File.separator + "vadtree_output_image" + File.separator + "vadtree_" + pid + "_" + this.fle_memory_image.getName()+ ".png");						 
						 try	{	fle_image.getParentFile().mkdirs();	} catch(Exception e){}
						 
						 String relative_path_vadtree_image = plugin_name + File.separator + "vadtree_output_image" + File.separator + "vadtree_" + pid + "_" + this.fle_memory_image.getName()+ ".png";
						 
						 if(this.nde_process != null)
						 {
							 nde_process.fle_vadtree_output_image = fle_image;
							 nde_process.relative_path_vadtree_image = relative_path_vadtree_image;
							 
						 }
						 
						 String path_converted_file = fle_image.getCanonicalPath();						 
						 
							path_converted_file = path_converted_file.substring(path_converted_file.indexOf(Driver.NAME_LOWERCASE)).trim();
							
							if(!path_converted_file.startsWith(File.separator))
								path_converted_file = File.separator + path_converted_file;
							
						 //solomon sonya @carpenter1010
							
							path_dot_file = fle_data.getCanonicalPath();
							
							path_dot_file = path_dot_file.substring(path_dot_file.indexOf(Driver.NAME_LOWERCASE)).trim();
							
							if(!path_dot_file.startsWith(File.separator))
								path_dot_file = File.separator + path_dot_file;
							
							if(!path_dot_file.endsWith(".dot"))
								path_dot_file = path_dot_file + ".dot";
							
							File fle_dot_file = new File("." + path_dot_file);
							
						 String command = "";
					    	
					    	
					    	
					    	if(driver.isWindows)
					    	{
					    		//output is working path from current execution location. do not end with closing "
					    		command = "\"" + Start.fle_graphviz_dot.getCanonicalPath() + "\" -T" + image_extension + " \"" + fle_dot_file.getCanonicalPath() + "\" -o \"." + path_converted_file;
					    		
					    		
					    	}
					    	else
					    	{		    		
					    		command = "dot -Tpng \"" + path_dot_file + "\" -o \"." + path_converted_file;
					    	}
					    	
					    	

					    	ProcessBuilder pb = null;				
							
							if(driver.isWindows)
								pb = new ProcessBuilder("cmd.exe", "/C",  command);
											
							else//(driver.isLinux)
								pb = new ProcessBuilder("/bin/bash", "-c",  command);
							
							//
							//redirect error stream
							//
							pb.redirectErrorStream(true); 
										
							//
							//instantiate new process
							//
							Process proc = pb.start();
								
							//output here will actually be the PNG file, thus write straight to location
							InputStream is =proc.getInputStream();
														
							int len = 0;
							byte [] array = new byte[4048]; 
							
							while((len = is.read(array)) >= 0)
							{
								String s = new String (array);
								/*if(s.toLowerCase().contains("png"))
								{
									driver.directive(s);
									//from here, we can see that the output is each PNG file, however, we need to catch each PNG file and write out separately
								}*/
									
								//fos.write(array, 0, len);
								
								sp("vad");
							}
									      
							//try	{	fos.flush();} catch(Exception e){}
							//try	{	fos.close();} catch(Exception e){}
														        
						   			      
						   //clean up			    
						    try	{	proc.destroy();			}	catch(Exception e){}
						    
						   
						    //
							//NOTIFY
							//			
							//sp("\nNOTE: If writing to dot file was successful, converted output file has been written to --> " + path_converted_file + "\n");
						 
						 
					 }
					 catch(Exception e){driver.directive("unable to create image file in " + this.myClassName);}
					
				 }
			 }
			 
			 else if(pw != null)
			 {
				 pw.println(line);
				 pw.flush();
			 }
			 
		 }
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "create_vad_walk_dot_file", e);
		}
		
		return false;
	}
		
	

	
	
	/**
	 * create dot file now, and then use a utility like graphviz to view it
	 * on linux machine, convert dot file to png or jpg via
	 * dot -Tpng infected.dot -o infected.png
	 * dot -Tjpg infected.dot > processes.jpg
	 * @return
	 */
	public boolean DEPRECATED_create_vad_walk_dot_file_DEPRECATED()
	{
		try
		{
			String image_extension = "png";
			
			String time_stamp = driver.get_time_stamp("_");
			String path_dot_file = path_fle_analysis_directory + this.plugin_name + File.separator + "_" + plugin_name + "_" + this.fle_memory_image.getName() + ".dot";
			path_dot_file = path_dot_file.substring(path_dot_file.indexOf(Driver.NAME_LOWERCASE)).trim();
			
			if(!path_dot_file.startsWith(File.separator))
				path_dot_file = File.separator + path_dot_file;
			
			if(!path_dot_file.endsWith(".dot"))
				path_dot_file = path_dot_file + ".dot";
			
			
			
			String path_converted_file = path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + "_" + this.fle_memory_image.getName() + "." + image_extension;
			path_converted_file = path_converted_file.substring(path_converted_file.indexOf(Driver.NAME_LOWERCASE)).trim();
			
			if(!path_converted_file.startsWith(File.separator))
				path_converted_file = File.separator + path_converted_file;
											
			String relative_path_to_converted_dot_process_image = plugin_name + File.separator + "_" + plugin_name + "_" + this.fle_memory_image.getName() + "." + image_extension; 
			
			String cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\"" + " -f " + "\"" + fle_memory_image.getCanonicalPath().trim() + "\"" + " --profile=" + PROFILE + " " + plugin_name + " --output=dot --output-file=\"." + path_dot_file.trim().replace(File.separator,"/");
			
			
			
			//
			//NOTIFY
			//
			if(parent.DEBUG)
				sop("[" + plugin_name + " - dot file]\t Executing command --> " + cmd);
			
			//
			//EXECUTE COMMAND!
			//
			ProcessBuilder process_builder = null;				
			
			if(driver.isWindows)
				process_builder = new ProcessBuilder("cmd.exe", "/C",  cmd);
							
			else//(driver.isLinux)
				process_builder = new ProcessBuilder("/bin/bash", "-c",  cmd);
			
			//
			//redirect error stream
			//
			process_builder.redirectErrorStream(true); 
						
			//
			//instantiate new process
			//
			Process process = process_builder.start();
						
					      
			BufferedReader brIn = new BufferedReader(new InputStreamReader(process.getInputStream()));
			
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

		        	//sp(" " + line);		        	
		        }
	        	        		        		        	                		        		      
		    }
		    catch(Exception e)
		    {
		    	driver.sop("check plugin process execution " + "" + plugin_name + " dot" + " - " + cmd);
		    }
		        
		      
		   //clean up
		    try	{ 	brIn.close();       		}	catch(Exception e){}
		    try	{	process.destroy();			}	catch(Exception e){}
		    try	{ 	line_iterator.close();      }	catch(Exception e){}
		   
		  
		    //
		    //convert, transform into png if possible
		    //
		    try
		    {
		    	//dot -Tjpg psscan.dot -o <path>.jpg  or dot -Tpng <path>.dot -o <path>.png
		    			    			    			    			    	
		    	String command = "";
		    	
		    	File fle_dot_file = new File("." + path_dot_file);
		    	
		    	if(driver.isWindows)
		    	{
		    		//output is working path from current execution location. do not end with closing "
		    		command = "\"" + Start.fle_graphviz_dot.getCanonicalPath() + "\" -T" + image_extension + " \"" + fle_dot_file.getCanonicalPath() + "\" -o \"." + path_converted_file;
		    		
		    		
		    	}
		    	else
		    	{		    		
		    		command = "dot -Tpng \"" + path_dot_file + "\" -o \"." + path_converted_file;
		    	}
		    	
		    	

		    	ProcessBuilder pb = null;				
				
				if(driver.isWindows)
					pb = new ProcessBuilder("cmd.exe", "/C",  command);
								
				else//(driver.isLinux)
					pb = new ProcessBuilder("/bin/bash", "-c",  command);
				
				//
				//redirect error stream
				//
				pb.redirectErrorStream(true); 
							
				//
				//instantiate new process
				//
				Process proc = pb.start();
					
				//output here will actually be the PNG file, thus write straight to location
				InputStream is =proc.getInputStream();
				
				File fle_converted_image = new File(path_fle_analysis_directory + plugin_name + File.separator + plugin_name + "_" + this.fle_memory_image.getName() + "." + image_extension);
				
				sop("\nAttempting to write VAD tree image file at: " + fle_converted_image);
				
				FileOutputStream fos = new FileOutputStream(fle_converted_image);
				
				int len = 0;
				byte [] array = new byte[4048]; 
				
				while((len = is.read(array)) >= 0)
				{
					String s = new String (array);
					if(s.toLowerCase().contains("png"))
					{
						driver.directive(s);
						//from here, we can see that the output is each PNG file, however, we need to catch each PNG file and write out separately
					}
						
					fos.write(array, 0, len);
					
					sp(".");
				}
						      
				try	{	fos.flush();} catch(Exception e){}
				try	{	fos.close();} catch(Exception e){}
											        
			   			      
			   //clean up			    
			    try	{	proc.destroy();			}	catch(Exception e){}
			    
			   
			    //
				//NOTIFY
				//			
				sp("\nNOTE: If writing to dot file was successful, converted output file has been written to --> " + path_converted_file + "\n");
		    	
		    }
		    catch(Exception e)
		    {
		    	//
				//NOTIFY
				//			
				sp("\n* * * NOTE: If writing to dot file was successful, output file has been written to --> " + path_dot_file + "\n");
		    }
		    
			
			
				
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "DEPRECATED_create_vad_walk_dot_file_DEPRECATED", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
}
