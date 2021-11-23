/**
 * This Snapshot thread handles calling 2 separate execution processes for each plugin: PRE and POST
 * 
 * It will use a timer to determine when both threads have stopped. At that point, it will run its comparison 
 * to create a list of changes detected after analyss
 * 
 * [+] means a new added entry found in POST but was not in PRE
 * [-] means an entry found in PRE but was not present in POST
 * [=] means an entry found both in POST and PRE
 * 
 * @author Solomon Sonya
 */

package Snapshot;

import Driver.*;
import Interface.*;
import Plugin.*;
import java.io.*;
import javax.swing.*;
import java.awt.event.*;
import java.util.TreeMap;
import java.util.Collections;
import java.util.LinkedList;

public class Snapshot_Plugin extends Thread implements Runnable, ActionListener
{
	public static final String myClassName = "Snapshot_Plugin";
	public static volatile Driver driver = new Driver();

	public volatile JTextArea_Solomon jtaConsole = null;	
	
	public volatile File fleImage1 = null;
	public volatile File fleImage2 = null;
	
	public volatile String profile1 = "";
	public volatile String profile2 = "";
	
	public volatile boolean EXECUTION_PLUGIN_PAIR_COMPLETE = false;
	
	public volatile Snapshot_Driver parent = null;
	
	public Plugin plugin = null;
	
	public volatile Timer tmr = null;
	
	public volatile boolean handle_interrupt = true;
	
	public volatile Process_Plugin process_pre = null;
	public volatile Process_Plugin process_post = null;
	
	public volatile boolean analyze_pslist = false;
	public volatile boolean analyze_psscan = false;
	public volatile boolean analyze_tree = false;
	public volatile boolean analyze_cmdline = false;
	public volatile boolean analyze_connections = false;
	public volatile boolean analyze_connscan = false;
	public volatile boolean analyze_consoles = false;
	public volatile boolean analyze_deskscan = false;
	public volatile boolean analyze_dlllist = false;
	public volatile boolean analyze_driverscan = false;
	public volatile boolean analyze_dumpcerts = false;
	public volatile boolean analyze_filescan = false;
	public volatile boolean analyze_getservicesids = false;
	public volatile boolean analyze_getsids = false;
	public volatile boolean analyze_handles = false;
	public volatile boolean analyze_hashdump = false;
	public volatile boolean analyze_hivelist = false;
	public volatile boolean analyze_iehistory = false;
	public volatile boolean analyze_mftparser = false;
	public volatile boolean analyze_modscan = false;
	public volatile boolean analyze_modules = false;
	public volatile boolean analyze_netscan = false;
	public volatile boolean analyze_sessions = false;
	public volatile boolean analyze_shimcache = false;
	public volatile boolean analyze_shellbags = false;
	public volatile boolean analyze_sockets = false;
	public volatile boolean analyze_sockscan = false;
	public volatile boolean analyze_svcscan = false;
	public volatile boolean analyze_timeliner = false;
	public volatile boolean analyze_userassist = false;

	
	public volatile LinkedList<String> list_added_PID = null;
	
	public volatile String plugin_text = "";
	
	public volatile TreeMap<String, String> tree_output_PRE = new TreeMap<String, String>();
	
	public volatile TreeMap<String, String> tree_analysis = new TreeMap<String, String>();
	public volatile LinkedList<String> list_analysis = new LinkedList<String>();
	
	public volatile TreeMap<String, String> tree_process_name_pre = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_process_name_post = new TreeMap<String, String>();
	
	/**lets us know the [+], [-], or [=] value*/
	public volatile LinkedList<String> list_keys_POST = new LinkedList<String>();
		
	
	public Snapshot_Plugin(Snapshot_Driver par, String PLUGIN_TEXT, File fleImage_1, String profile_1, File fleImage_2, String profile_2)
	{
		try
		{
			parent = par;
			plugin_text = PLUGIN_TEXT;
						
			
			if(par != null)
				jtaConsole = par.jtaConsole;
			
			//plugin
			plugin = Plugin.tree_plugins.get(PLUGIN_TEXT);
			
			
			fleImage1 = fleImage_1;
			fleImage2 = fleImage_2;
			
			profile1 = profile_1;
			profile2 = profile_2;
						
			
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
			//execute the plugin pair
			//continue from here, test and then commence execution. Goal is to run it completely, and then when finished, take the output linkedlist
			//and then process independently to extract the values we require into the tree
			
			if(Interface.fle_volatility == null || !Interface.fle_volatility.exists() || !Interface.fle_volatility.isFile())
			{
				driver.jop("* * * ERROR! You must select a valid volatility executable binary first! * * *");
			}
				
			else if(plugin != null && fleImage1 != null && fleImage1.exists() && fleImage1.isFile() && fleImage2 != null && fleImage2.exists() && fleImage2.isFile() && profile1 != null && !profile1.trim().equals("") && profile2 != null && !profile2.trim().equals(""))
			{
				sop("Commencing Snapshot execution pair for plugin [" + plugin.plugin_name + "]");
				//process_pre = new Process_Plugin(plugin, plugin.plugin_name, plugin.plugin_description, this.fleImage1, parent.file_attr_memory_image_1, Interface.fle_volatility.getCanonicalPath() + " -f " + this.fleImage1 + " " + plugin.plugin_name + " --profile=" + this.profile1, false, true, "PRE");
				//process_post = new Process_Plugin(plugin, plugin.plugin_name, plugin.plugin_description, this.fleImage2, parent.file_attr_memory_image_2, Interface.fle_volatility.getCanonicalPath() + " -f " + this.fleImage2 + " " + plugin.plugin_name + " --profile=" + this.profile2, false, true, "POST");
				
				process_pre =  new Process_Plugin(plugin, plugin.plugin_name, plugin.plugin_description, this.fleImage1, parent.file_attr_memory_image_1, "\"" + Interface.fle_volatility.getCanonicalPath().replace("\\", "/") + "\"" + " -f " + "\"" + this.fleImage1 + "\"" + " " + plugin.plugin_name + " --profile=" + this.profile1, false, true, "PRE", true);
				process_post = new Process_Plugin(plugin, plugin.plugin_name, plugin.plugin_description, this.fleImage2, parent.file_attr_memory_image_2, "\"" + Interface.fle_volatility.getCanonicalPath().replace("\\", "/") + "\"" + " -f " + "\"" + this.fleImage2 + "\"" + " " + plugin.plugin_name + " --profile=" + this.profile2, false, true, "POST", true);
				
				
				
				
				tmr = new Timer(2000, this);
				tmr.start();
			}
			
			else
			{
				directive("\n* * * Unable to commence snapshot analysis. Invalid object received:");
				directive("\t*Path to volatility: " + Interface.fle_volatility);
				directive("\t* * * Snapshot Image File 1 [PRE]: " + fleImage1);
				directive("\t* * * Snapshot Image Profile 1 [PRE]: " + profile1);
				directive("\t* * * Snapshot Image File 2 [POST]: " + fleImage2);
				directive("\t* * * Snapshot Image Profile 2 [POST]: " + profile2);
				
				if(plugin == null)
					directive("\t* * * COULD NOT FIND PLUGIN: " + plugin_text);
				else
					directive("\t* * * Plugin: " + plugin.plugin_name);
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == tmr)
			{
				process_interrupt();
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	
	private boolean process_interrupt()
	{
		try
		{
			if(!handle_interrupt)
				return false;
			
			handle_interrupt = false;
			
			//check if we're ready to continue
			if(process_pre.EXECUTION_COMPLETE && process_post.EXECUTION_COMPLETE && !EXECUTION_PLUGIN_PAIR_COMPLETE)
			{
				sop("Execution pair complete on plugin [" + this.plugin.plugin_name + "]. Commencing analysis of results now...");
				
				try	{	this.tmr.stop();} catch(Exception e){}
				
				//lock semaphore
				if(analyze_pslist)				
					return analyze_results_pslist_psscan();
				else if(analyze_psscan)				
					return analyze_results_pslist_psscan();
				else if(analyze_tree)				
					return analyze_results_pstree();
				else if(analyze_cmdline)				
					return this.analyze_results_cmdline();
				else if(analyze_connections)				
					return this.analyze_results_connections_connscan();
				else if(analyze_connscan)				
					return this.analyze_results_connections_connscan();
				else if(analyze_consoles)				
					return this.analyze_results_single_line_using_list(false, false);
				else if(analyze_deskscan)				
					return this.analyze_results_single_line_using_list(false, false);
				
				else if(analyze_dlllist)				
					return this.analyze_results_dlllist(true, false, false);
				
				else if(analyze_driverscan)				
					return this.analyze_results_driverscan();
				
				else if(analyze_dumpcerts)				
					return this.analyze_results_single_line_using_list(true, false);
				
				else if(analyze_filescan)				
					return this.analyze_results_filescan_hivelist();
				
				else if(analyze_hivelist)				
					return this.analyze_results_filescan_hivelist();
				
				else if(analyze_getservicesids)				
					return this.analyze_results_single_line_using_tree(false, false);
				
				else if(analyze_getsids)				
					return this.analyze_results_single_line_using_tree(true, false);
				
				else if(analyze_handles)				
					//return this.analyze_results_handles(false, false);
					return this.analyze_results_handles(false, false);
				
				else if(analyze_hashdump)				
					return this.analyze_results_single_line_using_tree(true, true);
				
				else if(analyze_iehistory)				
					return this.analyze_results_single_line_using_tree(true, true);
				
				else if(analyze_mftparser)				
					return this.analyze_results_mftparser(true, false);
				
				else if(analyze_modscan)				
					return this.analyze_results_modscan_modules(true, false);
				
				else if(analyze_modules)				
					return this.analyze_results_modscan_modules(true, false);
				
				else if(analyze_netscan)				
					return this.analyze_results_netscan(true, true);
				
				else if(analyze_sessions)				
					return this.analyze_results_sessions_shimcache(true, true);
				
				else if(analyze_shimcache)				
					return this.analyze_results_sessions_shimcache(true, false);
				
				else if(analyze_shellbags)				
					return this.analyze_results_shellbags(true, false);
				
				else if(analyze_sockets)				
					return this.analyze_results_sockets_sockscan(true, false);
				
				else if(analyze_sockscan)				
					return this.analyze_results_sockets_sockscan(true, false);
				
				else if(analyze_svcscan)				
					return this.analyze_results_svcscan(true, false);
				
				else if(analyze_timeliner)				
					return this.analyze_results_timeliner(true, false);
				
				else if(analyze_userassist)				
					return this.analyze_results_userassist(true, false);
				
			}
			
			handle_interrupt = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_interrupt", e);
		}
		
		handle_interrupt = true;
		return false;
	}
	
	private boolean analyze_results()
	{
		try
		{
			driver.directive("\nANALYZING RESULTS ON PLUGIN [" + this.plugin.plugin_name + "]");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	private boolean analyze_results_pslist_psscan()
	{
		try
		{
			//
			//NOTE: to analyze, just update how the key is procurred, and the rest should be fine.
			//you must update the key in both places below - SoloSonya@Carpenter1010
			//
			
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			//
			//init
			//
			String process_name = "";
			String PID = "";
			String key = "";
			
			//
			//analyze - take each value, normalize, and then store in the tree
			//
			String lower = "";
			String array [] = null;
			
			for(String line : process_pre.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(lower.contains("offset") && lower.contains("name") && lower.contains("pid") && lower.contains("ppid"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					
					
					//0x825c8830 System                    4      0     57      250 ------      0                                                              
					array = line.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					//[0] == 0x825c8830
					//[1] == Process Name
					
					process_name = array[1].trim();
					
					for(int i = 2; i <array.length; i++)
					{
						if(array[i] == null || array[i].trim().equals(""))
							continue;
						
						
						try	
						{ 
							PID = ""+Integer.parseInt(array[i].trim());
							
							//succeeded, break on the first PID we find
							break;
						}
						
						catch(Exception e)
						{
							//perhaps the Process name was more than one word, concat until we find the first integer for the PID
							process_name = process_name + " " + array[i].trim();
						}
					}
					
					//
					//store 
					//		
					tree_process_name_pre.put(PID, process_name);
					key = "Process Name: " + process_name + " PID: " + PID;
					this.tree_output_PRE.put(key, line);
					
					
				}//end overall try
				catch(Exception e)
				{
					continue;
				}
				
			}//end for loop for PRE analysis
			
			//
			//ANALYZE POST
			//
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(lower.contains("offset") && lower.contains("name") && lower.contains("pid") && lower.contains("ppid"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					//0x825c8830 System                    4      0     57      250 ------      0                                                              
					array = line.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					//[0] == 0x825c8830
					//[1] == Process Name
					
					process_name = array[1].trim();
					
					for(int i = 2; i <array.length; i++)
					{
						if(array[i] == null || array[i].trim().equals(""))
							continue;
						
						try	
						{ 
							PID = ""+Integer.parseInt(array[i].trim());
							
							//succeeded, break on the first PID we find
							break;
						}
						
						catch(Exception e)
						{
							//perhaps the Process name was more than one word, concat until we find the first integer for the PID
							process_name = process_name + " " + array[i].trim();
						}
					}
					
					//
					//store 
					//		
					key = "Process Name: " + process_name + " PID: " + PID;
					tree_process_name_post.put(PID,  process_name);
					
					//
					//determine if we have seen this key before
					//
					if(this.tree_output_PRE.containsKey(key))
					{
						this.tree_analysis.put("[ = ] \t" + key, this.tree_output_PRE.get(key) + "\t" + line);
					}
					else
					{						
						this.tree_analysis.put("[ + ] \t" + key, line);		
						
						if(this.list_added_PID == null)
							this.list_added_PID = new LinkedList<String>();
						
						this.list_added_PID.add(PID);
					}
					
					if(!list_keys_POST.contains(key))
						list_keys_POST.add(key);
					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}
				
				
				
			}//end for loop for POST analysis
			
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//			
			for(String pre_key : this.tree_output_PRE.keySet())
			{
				if(pre_key == null)
					continue;
				
				if(pre_key.trim().equals(""))
					continue;
				
				if(list_keys_POST.contains(pre_key))
					continue;//this is an [ = ] condition btw ;-)
				
				else//otw, its a key that existed in pre but is not found in post
					this.tree_analysis.put("[ - ] \t" + pre_key, this.tree_output_PRE.get(pre_key));											
				
			}
			
			//
			//COMPLETE
			//
			
			//write results
//			directive("\n");
//			for(String result_keys : this.tree_analysis.keySet())
//			{
//				driver.directive(result_keys + "\t" + this.tree_analysis.get(result_keys));
//			}
			
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_pslist_psscan", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	
	
	
	private boolean analyze_results_pstree()
	{
		try
		{
			//
			//NOTE: to analyze, just update how the key is procurred, and the rest should be fine.
			//you must update the key in both places below - SoloSonya@Carpenter1010
			//
			
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			//
			//init
			//
			String process_name = "";
			String PID = "";
			String key = "";
			
			//
			//analyze - take each value, normalize, and then store in the tree
			//
			String lower = "";
			String array [] = null;
			String array_tuple [] = null;
			
			for(String line : process_pre.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					
					if(lower.contains("name") && lower.contains("pid") && lower.contains("ppid"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					//.. 0x81ffbda0:winlogon.exe                           1800    552     14    204 2016-12-09 09:58:32 UTC+0000
                            
					line = line.substring(line.indexOf(":")+1).trim();
					
					array = line.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					//winlogon.exe                           1800    552     14    204 2016-12-09 09:58:32 UTC+0000
					
										
					process_name = array[0].trim();
					
					for(int i = 1; i <array.length; i++)
					{
						if(array[i] == null || array[i].trim().equals(""))
							continue;
						
						
						try	
						{ 
							PID = ""+Integer.parseInt(array[i].trim());
							
							//succeeded, break on the first PID we find
							break;
						}
						
						catch(Exception e)
						{
							//perhaps the Process name was more than one word, concat until we find the first integer for the PID
							process_name = process_name + " " + array[i].trim();
						}
					}
					
					//
					//store 
					//		
					tree_process_name_pre.put(PID, process_name);
					key = "Process Name: " + process_name + " PID: " + PID;
					this.tree_output_PRE.put(key, line);
					
					
				}//end overall try
				catch(Exception e)
				{
					continue;
				}
				
			}//end for loop for PRE analysis
			
			//
			//ANALYZE POST
			//
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(lower.contains("name") && lower.contains("pid") && lower.contains("ppid"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					line = line.substring(line.indexOf(":")+1).trim();
					
					array = line.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					//winlogon.exe                           1800    552     14    204 2016-12-09 09:58:32 UTC+0000
									
					process_name = array[0].trim();
					
					for(int i = 1; i <array.length; i++)
					{
						if(array[i] == null || array[i].trim().equals(""))
							continue;
						
						try	
						{ 
							PID = ""+Integer.parseInt(array[i].trim());
							
							//succeeded, break on the first PID we find
							break;
						}
						
						catch(Exception e)
						{
							//perhaps the Process name was more than one word, concat until we find the first integer for the PID
							process_name = process_name + " " + array[i].trim();
						}
					}
					
					//
					//store 
					//		
					key = "Process Name: " + process_name + " PID: " + PID;
					tree_process_name_post.put(PID,  process_name);
					
					//
					//determine if we have seen this key before
					//
					if(this.tree_output_PRE.containsKey(key))
					{
						this.tree_analysis.put("[ = ] \t" + key, this.tree_output_PRE.get(key) + "\t" + line);
					}
					else
					{						
						this.tree_analysis.put("[ + ] \t" + key, line);		
						
						if(this.list_added_PID == null)
							this.list_added_PID = new LinkedList<String>();
						
						this.list_added_PID.add(PID);
					}
					
					if(!list_keys_POST.contains(key))
						list_keys_POST.add(key);
					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}
				
				
				
			}//end for loop for POST analysis
			
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//			
			for(String pre_key : this.tree_output_PRE.keySet())
			{
				if(pre_key == null)
					continue;
				
				if(pre_key.trim().equals(""))
					continue;
				
				if(list_keys_POST.contains(pre_key))
					continue;//this is an [ = ] condition btw ;-)
				
				else//otw, its a key that existed in pre but is not found in post
					this.tree_analysis.put("[ - ] \t" + pre_key, this.tree_output_PRE.get(pre_key));											
				
			}
			
			//
			//COMPLETE
			//
			
			//write results
//			directive("\n");
//			for(String result_keys : this.tree_analysis.keySet())
//			{
//				driver.directive(result_keys + "\t" + this.tree_analysis.get(result_keys));
//			}
			
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_pstree", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	private boolean analyze_results_cmdline()
	{
		try
		{
			//
			//NOTE: to analyze, just update how the key is procurred, and the rest should be fine.
			//you must update the key in both places below - SoloSonya@Carpenter1010
			//
			
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			//
			//preprocess - add a last delimiter for the rest of analysis to work appropriately
			//
			process_pre.output.addLast("************************************************************************");
			process_post.output.addLast("************************************************************************");
			
			//
			//init
			//
			String line1 = "";
			String line2 = "";
			String key = "";
			
			//
			//analyze - take each value, normalize, and then store in the tree
			//
			String lower = "";
			String array [] = null;
			String array_tuple [] = null;
			
			for(String line : process_pre.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
										
					
					if(line.startsWith("*")) //reset and or process
					{						
						if(line1 == null || line1.trim().equals(""))
							continue;
							
						//here again, means we have a line1, and possibly a line2 as well

						//
						//store 
						//		
						key = "Process Name: " + line1 + "\t" + line2;
						this.tree_output_PRE.put(key, key);
						
						//reset
						line1 = "";
						line2 = "";
						continue;
						
					}
					else
					{
//						************************************************************************
//						System pid:      4
//						************************************************************************
//						smss.exe pid:    552
//						Command line : \SystemRoot\System32\smss.exe
//						************************************************************************
						
						if(line1 == null || line1.trim().equals(""))
						{
							line1 = line.trim();
							continue;
						}
						else
						{
							line2 = line;
							continue;
						}																	
						
					}
					

					
				}//end overall try
				catch(Exception e)
				{
					continue;
				}
				
			}//end for loop for PRE analysis
			
			//
			//ANALYZE POST
			//
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("*")) //reset and or process
					{						
						if(line1 == null || line1.trim().equals(""))
							continue;
							
						//here again, means we have a line1, and possibly a line2 as well

						//
						//store 
						//		
						key = "Process Name: " + line1 + "\t" + line2;
						this.tree_process_name_post.put(key, key);
						
						
						//
						//process - determine if we have seen this key before
						//
						if(this.tree_output_PRE.containsKey(key))
						{
							this.tree_analysis.put("[ = ] \t" + key, this.tree_output_PRE.get(key) + "\t" + this.tree_process_name_post.get(key));
						}
						else
						{						
							this.tree_analysis.put("[ + ] \t" + key, key);						
						}
						
						if(!list_keys_POST.contains(key))
							list_keys_POST.add(key);
						
						//reset
						line1 = "";
						line2 = "";
						
						
						continue;
						
					}
					else
					{
//						************************************************************************
//						System pid:      4
//						************************************************************************
//						smss.exe pid:    552
//						Command line : \SystemRoot\System32\smss.exe
//						************************************************************************
						
						if(line1 == null || line1.trim().equals(""))
						{
							line1 = line.trim();
							continue;
						}
						else
						{
							line2 = line;
							continue;
						}																	
						
					}
					
					
					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}
				
				
				
			}//end for loop for POST analysis
			
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//			
			for(String pre_key : this.tree_output_PRE.keySet())
			{
				if(pre_key == null)
					continue;
				
				if(pre_key.trim().equals(""))
					continue;
				
				if(list_keys_POST.contains(pre_key))
					continue;//this is an [ = ] condition btw ;-)
				
				else//otw, its a key that existed in pre but is not found in post
					this.tree_analysis.put("[ - ] \t" + pre_key, this.tree_output_PRE.get(pre_key));											
				
			}
			
			//
			//COMPLETE
			//
			
			
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_cmdline", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	
	private boolean analyze_results_connections_connscan()
	{
		try
		{
			//
			//NOTE: to analyze, just update how the key is procurred, and the rest should be fine.
			//you must update the key in both places below - SoloSonya@Carpenter1010
			//
			
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			//
			//init
			//
			String offset = "";
			String local_address = "";
			String remote_address = "";
			String process_name = "";
			String PID = "";
			String key = "";
			
			
			
			//
			//analyze - take each value, normalize, and then store in the tree
			//
			String lower = "";
			String array [] = null;
			String array_tuple [] = null;
			
			for(String line : process_pre.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(lower.contains("offset") && lower.contains("local") && lower.contains("remote") && lower.contains("pid"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					//0x81acf008	192.168.30.129:1347	54.83.43.69:80	888	
                           										
					array = line.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					LinkedList<String> list = new LinkedList<String>();
																				
					for(int i = 0; i <array.length; i++)
					{
						if(array[i] == null || array[i].trim().equals(""))
							continue;
						
						list.add(array[i].trim());						
					}
					
					offset = list.get(0);
					local_address = list.get(1);
					remote_address = list.get(2);
					PID = list.get(3);
					
					
					//
					//store 
					//		
					
					key = "PID: " + PID + " Local Address: " + local_address + " Remote Address: " + remote_address;
					this.tree_output_PRE.put(key, line);
					
					
				}//end overall try
				catch(Exception e)
				{
					continue;
				}
				
			}//end for loop for PRE analysis
			
			//
			//ANALYZE POST
			//
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(lower.contains("offset") && lower.contains("local") && lower.contains("remote") && lower.contains("pid"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					//0x81acf008	192.168.30.129:1347	54.83.43.69:80	888	
                           										
					array = line.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					LinkedList<String> list = new LinkedList<String>();
																				
					for(int i = 0; i <array.length; i++)
					{
						if(array[i] == null || array[i].trim().equals(""))
							continue;
						
						list.add(array[i].trim());						
					}
					
					offset = list.get(0);
					local_address = list.get(1);
					remote_address = list.get(2);
					PID = list.get(3);
					
					
					//
					//store 
					//							
					key = "PID: " + PID + " Local Address: " + local_address + " Remote Address: " + remote_address;										
					
					//
					//determine if we have seen this key before
					//
					if(this.tree_output_PRE.containsKey(key))
					{
						this.tree_analysis.put("[ = ] \t" + key, this.tree_output_PRE.get(key) + "\t" + line);
					}
					else
					{						
						this.tree_analysis.put("[ + ] \t" + key, line);						
					}
					
					if(!list_keys_POST.contains(key))
						list_keys_POST.add(key);
					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}
				
				
				
			}//end for loop for POST analysis
			
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//			
			for(String pre_key : this.tree_output_PRE.keySet())
			{
				if(pre_key == null)
					continue;
				
				if(pre_key.trim().equals(""))
					continue;
				
				if(list_keys_POST.contains(pre_key))
					continue;//this is an [ = ] condition btw ;-)
				
				else//otw, its a key that existed in pre but is not found in post
					this.tree_analysis.put("[ - ] \t" + pre_key, this.tree_output_PRE.get(pre_key));											
				
			}
			
			
			
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_connections", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	
	
	
	
	/**This one, we'll only provide feedback based on the results of the second list. We'll only place the added [+] entries*/
	private boolean analyze_results_single_line_using_list(boolean include_removed_entries, boolean indicate_duplicate_entries)
	{
		try
		{
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			String lower = "";
			String trim = "";
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(lower.contains("offset") && lower.contains("local") && lower.contains("remote") && lower.contains("pid"))
						continue;
					
					if(line.startsWith("---"))
						continue;						
											
					
					//
					//determine if we have seen this key before
					//
					if(this.process_pre.output.contains(line) || this.process_pre.output.contains(trim))
					{
						if(indicate_duplicate_entries)
							this.list_analysis.addLast("[ = ] \t" + line);
						
						continue;
					}
					
					//otw, add!
						this.list_analysis.add("[ + ] \t" + line);					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for POST analysis	
			
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//		
			if(include_removed_entries)
			{
				for(String pre_key : process_pre.output)
				{
					if(pre_key == null)
						continue;
					
					if(pre_key.trim().equals(""))
						continue;
					
					if(process_post.output.contains(pre_key))
						continue;//this is an [ = ] condition btw ;-)
					
					else//otw, its a key that existed in pre but is not found in post
						this.list_analysis.add("[ - ] \t" + pre_key);														
					
				}
			}
			
			
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_single_line_using_list", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	
	
	private boolean analyze_results_dlllist(boolean include_removed_entries, boolean indicate_duplicate_entries, boolean include_pid_in_output)
	{
		try
		{
			//
			//NOTE: to analyze, just update how the key is procurred, and the rest should be fine.
			//you must update the key in both places below - SoloSonya@Carpenter1010
			//
			
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			//
			//init
			//
			String process_name_pid = "";
			String key = "";
			
			
			
			//
			//analyze - take each value, normalize, and then store in the tree
			//
			String lower = "";
			String array [] = null;
			String array_tuple [] = null;
			
			String process_name = "";
			String pid = "";
			String command_line = "";
			
			String base = "";
			String size = "";
			String load_count = "";
			String path = "";
			
			TreeMap<String, String> tree_pre = new TreeMap<String, String>();
			TreeMap<String, String> tree_post = new TreeMap<String, String>();
			
			//
			//PRE
			//
			
			for(String line : process_pre.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					if(lower.contains("base") && lower.contains("size") && lower.contains("loadcount") && lower.contains("path"))
						continue;
					
					if(line.startsWith("*"))
					{
						process_name = "";
						pid = "";
						command_line = "";
						
						continue;
					}
					
					if(line.contains(" pid:"))
					{
						array_tuple = line.split(" pid:");
						
						process_name = array_tuple[0].trim();
						pid = array_tuple[1].trim();
						
						command_line = "";
					}
					else if(lower.contains("command line"))
					{
						command_line = line.substring(line.indexOf(":")+1);
					}
					else if(lower.startsWith("0x"))
					{
						//reinit
						base = "";
						size = "";
						load_count = "";
						path = "";
						
						//process
						array_tuple = line.split(" ");
						
						for(String token : array_tuple)
						{
							if(token == null)
								continue;
							
							token = token.trim();
							
							if(token.equals(""))
								continue;
							
							if(base.equals(""))
								base = token;
							else if(size.equals(""))
								size = token;
							else if(load_count.equals(""))
								load_count = token;
							else
								path = path + " " + token;
							
						}
						
						path = path.trim();
						
						//store
						if(include_pid_in_output) //including the PID since even the process name is the same, but a different pid can make the output noisy
							tree_pre.put(process_name + "\t " + command_line + "\t " + path, "PID: " + pid + "\t base: " + base + "\t size: " + size + "\t load count: " + load_count);						
						else
							tree_pre.put(process_name + "\t " + command_line + "\t " + path, "base: " + base + "\t size: " + size + "\t load count: " + load_count);
					}
					
					
					
				}//end overall try
				catch(Exception e)
				{
					continue;
				}
				
			}//end for loop for PRE analysis
			
			
			//
			//POST
			//
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					if(lower.contains("base") && lower.contains("size") && lower.contains("loadcount") && lower.contains("path"))
						continue;
					
					if(line.startsWith("*"))
					{
						process_name = "";
						pid = "";
						command_line = "";
						
						continue;
					}
					
					if(line.contains(" pid:"))
					{
						array_tuple = line.split(" pid:");
						
						process_name = array_tuple[0].trim();
						pid = array_tuple[1].trim();
						
						command_line = "";
					}
					else if(lower.contains("command line"))
					{
						command_line = line.substring(line.indexOf(":")+1);
					}
					else if(lower.startsWith("0x"))
					{
						//reinit
						base = "";
						size = "";
						load_count = "";
						path = "";
						
						//process
						array_tuple = line.split(" ");
						
						for(String token : array_tuple)
						{
							if(token == null)
								continue;
							
							token = token.trim();
							
							if(token.equals(""))
								continue;
							
							if(base.equals(""))
								base = token;
							else if(size.equals(""))
								size = token;
							else if(load_count.equals(""))
								load_count = token;
							else
								path = path + " " + token;
							
						}
						
						path = path.trim();
						
						//store
						//tree_post.put(process_name + "\t " + command_line + "\t " + path, "PID: " + pid + "\t base: " + base + "\t size: " + size + "\t load count: " + load_count);
						
						//store
						if(include_pid_in_output) //including the PID since even the process name is the same, but a different pid can make the output noisy
							tree_post.put(process_name + "\t " + command_line + "\t " + path, "PID: " + pid + "\t base: " + base + "\t size: " + size + "\t load count: " + load_count);						
						else
							tree_post.put(process_name + "\t " + command_line + "\t " + path, "base: " + base + "\t size: " + size + "\t load count: " + load_count);
						
					}
					
					
					
				}//end overall try
				catch(Exception e)
				{
					continue;
				}
				
			}//end for loop for POST analysis
			
			//
			//ANALYSIS
			//
			String tree_value = "";
			for(String TREE_KEY : tree_post.keySet())
			{
				if(TREE_KEY == null)
					continue;
				
				if(tree_pre.containsKey(TREE_KEY))
				{
					if(!tree_post.get(TREE_KEY).equalsIgnoreCase(tree_pre.get(TREE_KEY)))
						this.tree_analysis.put("[ <> ] \t" + TREE_KEY, "[POST]: " + tree_post.get(TREE_KEY) + "\t[PRE]: " + tree_pre.get(TREE_KEY));
					else if(indicate_duplicate_entries)
						this.tree_analysis.put("[ = ] \t" + TREE_KEY, tree_post.get(TREE_KEY));
				}
				else
					this.tree_analysis.put("[ + ] \t" + TREE_KEY, tree_post.get(TREE_KEY));
			}
			
			if(include_removed_entries)
			{
				for(String PRE_KEY : tree_pre.keySet())
				{
					if(!tree_post.containsKey(PRE_KEY))
						this.tree_analysis.put("[ - ] \t" + PRE_KEY, tree_pre.get(PRE_KEY));
				}
			}
			
			
						
			
			
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_dlllist", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	private boolean analyze_results_single_line_using_tree(boolean include_removed_entries, boolean indicate_duplicate_entries)
	{
		try
		{
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			String lower = "";
			String trim = "";
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
															
										
											
					
					//
					//determine if we have seen this key before
					//
					if(this.process_pre.output.contains(line) || this.process_pre.output.contains(trim))
					{
						if(indicate_duplicate_entries)
							this.tree_analysis.put("[ = ] \t" + line, "");
						
						continue;
					}
					
					//otw, add!
					this.tree_analysis.put("[ + ] \t" + line, "");					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for POST analysis	
			
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//		
			if(include_removed_entries)
			{
				for(String pre_key : process_pre.output)
				{
					if(pre_key == null)
						continue;
					
					if(pre_key.trim().equals(""))
						continue;
					
					if(process_post.output.contains(pre_key))
						continue;//this is an [ = ] condition btw ;-)
					
					else//otw, its a key that existed in pre but is not found in post
						this.tree_analysis.put("[ - ] \t" + pre_key, "");														
					
				}
			}
						
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_single_line_using_tree", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	private boolean analyze_results_sessions_shimcache(boolean include_removed_entries, boolean indicate_duplicate_entries)
	{
		try
		{
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			String lower = "";
			String trim = "";
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
															
										
					if(lower.contains("pagedpoolstart") || lower.startsWith("session") || lower.startsWith("*") || lower.startsWith("image"))						
						continue;	
					
					if(lower.contains("last modified") && lower.contains("last update") && lower.contains("path"))						
						continue;	
					
					//
					//determine if we have seen this key before
					//
					if(this.process_pre.output.contains(line) || this.process_pre.output.contains(trim))
					{
						if(indicate_duplicate_entries)
							this.tree_analysis.put("[ = ] \t" + line, "");
						
						continue;
					}
					
					//otw, add!
					this.tree_analysis.put("[ + ] \t" + line, "");					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for POST analysis	
			
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//		
			if(include_removed_entries)
			{
				for(String pre_key : process_pre.output)
				{
					if(pre_key == null)
						continue;
					
					if(pre_key.trim().equals(""))
						continue;
					
					if(pre_key.toLowerCase().startsWith("last modified"))						
						continue;
					
					if(pre_key.startsWith("---"))
						continue;
					
					if(process_post.output.contains(pre_key))
						continue;//this is an [ = ] condition btw ;-)
					
					else//otw, its a key that existed in pre but is not found in post
						this.tree_analysis.put("[ - ] \t" + pre_key, "");														
					
				}
			}
						
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_sessions_shimcache", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	private boolean analyze_results_shellbags(boolean include_removed_entries, boolean indicate_duplicate_entries)
	{
		try
		{
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			String lower = "";
			String trim = "";
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
															
					if(lower.startsWith("last updated"))
						continue;
					
					if(!lower.contains("utc+"))
						continue;
					
					//
					//determine if we have seen this key before
					//
					if(this.process_pre.output.contains(line) || this.process_pre.output.contains(trim))
					{
						if(indicate_duplicate_entries)
							this.tree_analysis.put("[ = ] \t" + line, "");
						
						continue;
					}
					
					//otw, add!
					this.tree_analysis.put("[ + ] \t" + line, "");					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for POST analysis	
			
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//		
			if(include_removed_entries)
			{
				for(String pre_key : process_pre.output)
				{
					if(pre_key == null)
						continue;
					
					if(pre_key.trim().equals(""))
						continue;
					
					if(pre_key.toLowerCase().startsWith("last updated"))
						continue;
					
					if(!pre_key.toLowerCase().contains("utc+"))
						continue;
															
					if(process_post.output.contains(pre_key))
						continue;//this is an [ = ] condition btw ;-)
					
					else//otw, its a key that existed in pre but is not found in post
						this.tree_analysis.put("[ - ] \t" + pre_key, "");														
					
				}
			}
						
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_shellbags", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	private boolean analyze_results_svcscan(boolean include_removed_entries, boolean indicate_duplicate_entries)
	{
		try
		{
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			String lower = "";
			String trim = "";
			String key = "";
			String value_store = "";
			
			String offset = "";
			String order = "";
			String start = "";
			String process_id = "";
			String service_name = "";
			String display_name = "";
			String service_type = "";
			String service_state = "";
			String binary_path = "";
			
			String value = "";
			//
			//FIRST PASS
			//continue from here. problem... everything is considered a new entry, and if the line below doesn't have the same entry, then it is considered not there
			//instead, we need to prepopulate a list first, and then check that tree against the current entries
			//
			
			TreeMap<String, String> tree_keys_pre = new TreeMap<String, String>();
			TreeMap<String, String> tree_keys_post = new TreeMap<String, String>();
			
			for(String line : process_pre.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
					
					if(!line.contains(":"))
						continue;
					
					value = line.substring(line.indexOf(":")+1).trim();
															
					if(lower.startsWith("binary path") )
					{
						binary_path = value;	
						
						//check if we have full entries
						if(!service_type.equals("") || !service_state.equals("") || !start.equals(""))
						{							
							//store!
							//key = "Service Name: " + service_name + "\tDisplay Name: " + display_name + "\tPID: " + process_id + "\tStart: " + start + "\tService Type: " + service_type + "\tService State: " + service_state + "\tBinary Path: " + binary_path + "\tOrder: " + order + "\tOffset: " + offset ;
							key = "Service Name: " + service_name + "\tDisplay Name: " + display_name + "\tStart: " + start + "\tService Type: " + service_type + "\tService State: " + service_state;
							
							//value_store
							value_store = "\tPID: " + process_id + "\tBinary Path: " + binary_path + "\tOrder: " + order + "\tOffset: " + offset ;
							
							//first pass, store the key
							tree_keys_pre.put(key, value_store);
							

						
						//reinit
						offset = value.trim();
						order = "";
						start = "";
						process_id = "";
						service_name = "";
						display_name = "";
						service_type = "";
						service_state = "";
						binary_path = "";		
						
						}
					}
					
					else if(lower.startsWith("offset"))
						offset = value;	
					else if(lower.startsWith("order"))
						order = value;
					else if(lower.startsWith("start"))
						start = value;
					else if(lower.startsWith("process id"))
						process_id = value;
					else if(lower.startsWith("service name"))
						service_name = value;
					else if(lower.startsWith("display name"))
						display_name = value;
					else if(lower.startsWith("service type"))
						service_type = value;
					else if(lower.startsWith("service state"))
						service_state = value;
					else if(lower.startsWith("binary path"))
						binary_path = value;																					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for PRE key/value pair population	
			
			
			//
			//POST KEY/PAIR POPULATION
			//
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
					
					if(!line.contains(":"))
						continue;
					
					value = line.substring(line.indexOf(":")+1).trim();
															
					if(lower.startsWith("binary path") )
					{
						binary_path = value;	
						
						//check if we have full entries
						if(!service_type.equals("") || !service_state.equals("") || !start.equals(""))
						{							
							//store!
							//key = "Service Name: " + service_name + "\tDisplay Name: " + display_name + "\tPID: " + process_id + "\tStart: " + start + "\tService Type: " + service_type + "\tService State: " + service_state + "\tBinary Path: " + binary_path + "\tOrder: " + order + "\tOffset: " + offset ;
							key = "Service Name: " + service_name + "\tDisplay Name: " + display_name + "\tStart: " + start + "\tService Type: " + service_type + "\tService State: " + service_state;
							
							//value_store
							value_store = "\tPID: " + process_id + "\tBinary Path: " + binary_path + "\tOrder: " + order + "\tOffset: " + offset ;
							
							//first pass, store the key
							tree_keys_post.put(key, value_store);
							

						
						//reinit
						offset = value.trim();
						order = "";
						start = "";
						process_id = "";
						service_name = "";
						display_name = "";
						service_type = "";
						service_state = "";
						binary_path = "";		
						
						}
					}
					
					else if(lower.startsWith("offset"))
						offset = value;					
					else if(lower.startsWith("order"))
						order = value;
					else if(lower.startsWith("start"))
						start = value;
					else if(lower.startsWith("process id"))
						process_id = value;
					else if(lower.startsWith("service name"))
						service_name = value;
					else if(lower.startsWith("display name"))
						display_name = value;
					else if(lower.startsWith("service type"))
						service_type = value;
					else if(lower.startsWith("service state"))
						service_state = value;
					else if(lower.startsWith("binary path"))
						binary_path = value;																					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for PRE key/value pair population	
			
			//
			//ANALYSIS
			//
			for(String key_entry : tree_keys_post.keySet())
			{
				if(tree_keys_pre.containsKey(key_entry))
				{
					if(indicate_duplicate_entries)
						this.tree_analysis.put("[ = ] \t" + key_entry, "[POST]\t" + tree_keys_post.get(key_entry) + "\t[PRE]\t" + tree_keys_pre.get(key_entry));
				}
				
				else//new entry!
					this.tree_analysis.put("[ + ] \t" + key_entry, "[POST]\t" + tree_keys_post.get(key_entry));
			}
			
			//
			//removed entries
			//
			if(include_removed_entries)
			{
				for(String key_entry : tree_keys_pre.keySet())
				{
					if(!tree_keys_post.containsKey(key_entry) && !tree_analysis.containsKey(key_entry))
						this.tree_analysis.put("[ - ] \t" + key_entry, "[PRE]\t" + tree_keys_pre.get(key_entry));	
					//else if(tree_keys_post.containsKey(key_entry) && tree_keys_post.get(key_entry) != null && tree_keys_pre.get(key_entry) != null && !tree_keys_pre.get(key_entry).equalsIgnoreCase(tree_keys_post.get(key_entry)))
						//this.tree_analysis.put("[ <> ] \t" + key_entry, tree_keys_pre.get(key_entry));
				}
			}
			
			//store 
						
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_svcscan", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	private boolean analyze_results_mftparser(boolean include_removed_entries, boolean indicate_duplicate_entries)
	{
		try
		{
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(process_post.list_prefetch == null)
			{
				if(process_pre.list_prefetch != null)
				{
					for(String entry : process_pre.list_mft)
					{
						if(entry == null)
							continue;
						
						if(entry.trim().equals(""))
							continue;
						
						//otw
						this.list_analysis.add("[ - ] \t" + entry);
					}//end for										
				}
				
				//stop here since the other list was null				
				return false;
			}
			
			if(process_pre.list_prefetch == null)
			{
				if(process_post.list_prefetch != null)
				{
					for(String entry : process_post.list_mft)
					{
						if(entry == null)
							continue;
						
						if(entry.trim().equals(""))
							continue;
						
						//otw
						this.list_analysis.add("[ + ] \t" + entry);
					}//end for										
				}
				
				//stop here since the other list was null				
				return false;
			}
			
			String lower = "";
			String trim = "";
			
			//sort the list
			Collections.sort(process_post.list_mft);
			
			for(String line : process_post.list_mft)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
															
										
											
					
					//
					//determine if we have seen this key before
					//
					if(this.process_pre.list_mft.contains(line) || this.process_pre.list_mft.contains(trim))
					{
						if(indicate_duplicate_entries)
							this.list_analysis.add("[ = ] \t" + line);
						
						continue;
					}
					
					//otw, add!
					this.list_analysis.add("[ + ] \t" + line);					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for POST analysis	
			
			//sort the list
			Collections.sort(process_pre.list_mft);
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//		
			if(include_removed_entries)
			{
				for(String pre_key : process_pre.list_mft)
				{
					if(pre_key == null)
						continue;
					
					if(pre_key.trim().equals(""))
						continue;
					
					if(process_post.list_mft.contains(pre_key) || process_post.list_mft.contains(pre_key.trim()))
						continue;//this is an [ = ] condition btw ;-)
					
					else//otw, its a key that existed in pre but is not found in post
						this.list_analysis.add("[ - ] \t" + pre_key);														
					
				}
			}
						
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_mftparser", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	
	
	private boolean analyze_results_driverscan()
	{
		try
		{
			//
			//NOTE: to analyze, just update how the key is procurred, and the rest should be fine.
			//you must update the key in both places below - SoloSonya@Carpenter1010
			//
			
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			//
			//init
			//
			String process_name_pid = "";
			String key = "";
			
			
			
			//
			//analyze - take each value, normalize, and then store in the tree
			//
			String lower = "";
			String array [] = null;
			String array_tuple [] = null;
			
			for(String line : process_pre.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					if(lower.contains("base") && lower.contains("size") && lower.contains("loadcount") && lower.contains("path"))
						continue;
					
					
					
					
					if(!lower.startsWith("0x"))
						continue;
                           										
					key = line.substring(line.lastIndexOf("0x")+1);
					
					//get rid of remaining space
					key = key.substring(key.indexOf(" ")+1).trim();
															
					//
					//store 
					//						
					this.tree_output_PRE.put(key, line);
					
					
				}//end overall try
				catch(Exception e)
				{
					continue;
				}
				
			}//end for loop for PRE analysis
			
			//
			//ANALYZE POST
			//
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					if(lower.contains("base") && lower.contains("size") && lower.contains("loadcount") && lower.contains("path"))
						continue;
					
					
					if(!lower.startsWith("0x"))
						continue;
                           										
					key = line.substring(line.lastIndexOf("0x")+1);
					
					//get rid of remaining space
					key = key.substring(key.indexOf(" ")+1).trim();
																			
					//
					//determine if we have seen this key before
					//
					if(this.tree_output_PRE.containsKey(key))
					{
						//this.tree_analysis.put("[ = ] \t" + key, this.tree_output_PRE.get(key) + "\t" + line);
					}
					else
					{						
						this.tree_analysis.put("[ + ] \t" + key, line);						
					}
					
					if(!list_keys_POST.contains(key))
						list_keys_POST.add(key);
					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}
				
				
				
			}//end for loop for POST analysis
			
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//			
			for(String pre_key : this.tree_output_PRE.keySet())
			{
				if(pre_key == null)
					continue;
				
				if(pre_key.trim().equals(""))
					continue;
				
				if(list_keys_POST.contains(pre_key))
					continue;//this is an [ = ] condition btw ;-)
				
				else//otw, its a key that existed in pre but is not found in post
					this.tree_analysis.put("[ - ] \t" + pre_key, this.tree_output_PRE.get(pre_key));											
				
			}
			
			
			
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_driverscan", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	private boolean analyze_results_filescan_hivelist()
	{
		try
		{
			//
			//NOTE: to analyze, just update how the key is procurred, and the rest should be fine.
			//you must update the key in both places below - SoloSonya@Carpenter1010
			//
			
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			//
			//init
			//
			String process_name_pid = "";
			String key = "";
			
			
			
			//
			//analyze - take each value, normalize, and then store in the tree
			//
			String lower = "";
			String array [] = null;
			String array_tuple [] = null;
			
			for(String line : process_pre.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					if(lower.contains("offset") && lower.contains("ptr") && lower.contains("access") && lower.contains("name"))
						continue;		
					
					if(lower.contains("virtual") && lower.contains("offset") && lower.contains("name"))
						continue;		
					
					if(!lower.startsWith("0x"))
						continue;
					
					if(!line.contains("\\") && !line.contains("/"))
						continue;
                           										
					key = line.substring(line.indexOf("\\")+1);
					
					if(key == null || key.length() < 1)
						key = line.substring(line.indexOf("/")+1);
					
					if(key == null || key.length() < 1)
						continue;
					
					//get rid of remaining space
					key = key.trim();
															
					//
					//store 
					//						
					this.tree_output_PRE.put(key, "");
					
					
				}//end overall try
				catch(Exception e)
				{
					continue;
				}
				
			}//end for loop for PRE analysis
			
			//
			//ANALYZE POST
			//
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					if(lower.contains("offset") && lower.contains("ptr") && lower.contains("access") && lower.contains("name"))
						continue;	
					
					if(lower.contains("virtual") && lower.contains("offset") && lower.contains("name"))
						continue;		
					
					if(!lower.startsWith("0x"))
						continue;
					
					if(!line.contains("\\") && !line.contains("/"))
						continue;
                           										
					key = line.substring(line.indexOf("\\")+1);
					
					if(key == null || key.length() < 1)
						key = line.substring(line.indexOf("/")+1);
					
					if(key == null || key.length() < 1)
						continue;
					
					//get rid of remaining space
					key = key.trim();
																			
					//
					//determine if we have seen this key before
					//
					if(this.tree_output_PRE.containsKey(key))
					{
						//this.tree_analysis.put("[ = ] \t" + key, this.tree_output_PRE.get(key) + "\t" + line);
					}
					else
					{						
						this.tree_analysis.put("[ + ] \t" + key, "");						
					}
					
					if(!list_keys_POST.contains(key))
						list_keys_POST.add(key);
					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}
				
				
				
			}//end for loop for POST analysis
			
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//			
			for(String pre_key : this.tree_output_PRE.keySet())
			{
				if(pre_key == null)
					continue;
				
				if(pre_key.trim().equals(""))
					continue;
				
				if(list_keys_POST.contains(pre_key))
					continue;//this is an [ = ] condition btw ;-)
				
				else//otw, its a key that existed in pre but is not found in post
					this.tree_analysis.put("[ - ] \t" + pre_key, this.tree_output_PRE.get(pre_key));											
				
			}
			
			
			
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_filescan_hivelist", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	public boolean sop(String out)
	{
		try
		{
			if(parent != null)
				parent.sop(out);
			else			
				driver.sop(out);
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	public boolean directive(String out)
	{
		try
		{
			if(parent != null)
				parent.directive(out);
			else			
				driver.directive(out);
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "directive", e);
		}
		
		return false;
	}
	
	
	private boolean analyze_results_modscan_modules(boolean include_removed_entries, boolean indicate_duplicate_entries)
	{
		try
		{
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			String lower = "";
			String trim = "";
			String key = "";
			String value = "";
			String [] array = null;
			
			TreeMap<String, String> tree_post = new TreeMap<String, String>();
			TreeMap<String, String> tree_pre = new TreeMap<String, String>();
			
			//
			//PROCESS POST
			//
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
					
					
					//
					//dismiss
					//
					if(lower.contains("offset") && lower.contains("name") && lower.contains("base") && lower.contains("size"))
						continue;	
																				
					//
					//reinit
					//
					key = "";
					value = "";
					
					//
					//split
					//
					array = line.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					for(String token : array)
					{
						if(token == null || token.trim().equals(""))
							continue;
						
						token = token.trim();
						
						if(token.startsWith("0x"))
							continue;
						
						if(key.equals(""))
						{
							key = token;
							break;
						}
						else //if(value.equals(""))
							value = value + " " + token;
					}
					
					if(!line.contains("\\"))
						continue;
					
					value = line.substring(line.indexOf("\\"));
					
					value = value.trim();
					
					//ensure we have proper value
					if(value.equals(""))
						continue;
					
					if(value == null)
						continue;
					
					tree_post.put(key, value);			
															
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for POST analysis	
			
			
			//
			//PROCESS PRE
			//
			for(String line : process_pre.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
					
					
					//
					//dismiss
					//
					if(lower.contains("offset") && lower.contains("name") && lower.contains("base") && lower.contains("size"))
						continue;	
																				
					//
					//reinit
					//
					key = "";
					value = "";
					
					//
					//split
					//
					array = line.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					for(String token : array)
					{
						if(token == null || token.trim().equals(""))
							continue;
						
						token = token.trim();
						
						if(token.startsWith("0x"))
							continue;
						
						if(key.equals(""))
						{
							key = token;
							break;
						}
						else //if(value.equals(""))
							value = value + " " + token;
					}
					
					if(!line.contains("\\"))
						continue;
					
					value = line.substring(line.indexOf("\\"));
					
					value = value.trim();
					
					//ensure we have proper value
					if(value.equals(""))
						continue;
					
					if(value == null)
						continue;
					
					tree_pre.put(key, value);			
															
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for PRE analysis	
			
			
			//
			//ANALYSIS
			//
			String tree_value = "";
			for(String TREE_KEY : tree_post.keySet())
			{
				if(TREE_KEY == null)
					continue;
				
				if(tree_pre.containsKey(TREE_KEY))
				{
					if(!tree_post.get(TREE_KEY).equalsIgnoreCase(tree_pre.get(TREE_KEY)))
						this.tree_analysis.put("[ <> ] \t" + TREE_KEY, "[POST]: " + tree_post.get(TREE_KEY) + "\t[PRE]: " + tree_pre.get(TREE_KEY));
					else if(indicate_duplicate_entries)
						this.tree_analysis.put("[ = ] \t" + TREE_KEY, tree_post.get(TREE_KEY));
				}
				else
					this.tree_analysis.put("[ + ] \t" + TREE_KEY, tree_post.get(TREE_KEY));
			}
			
			if(include_removed_entries)
			{
				for(String PRE_KEY : tree_pre.keySet())
				{
					if(!tree_post.containsKey(PRE_KEY))
						this.tree_analysis.put("[ - ] \t" + PRE_KEY, tree_pre.get(PRE_KEY));
				}
			}
			
			//this.tree_analysis.put("[ - ] \t" + tree_key, pre_key);					
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_modscan_modules", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	private boolean analyze_results_netscan(boolean include_removed_entries, boolean indicate_duplicate_entries)
	{
		try
		{
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			String lower = "";
			String trim = "";
			String offset = "";
			String protocol = "";
			String local_address = "";
			String foreign_address = "";
			String state = "";
			String PID = "";
			String owner = "";
			String created = "";
			
			String [] array = null;
			String tree_key = "";
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
					
					
					//
					//dismiss
					//
					if(lower.contains("offset") && lower.contains("proto") && lower.contains("local") && lower.contains("foreign") && lower.contains("address") && lower.contains("state"))
						continue;	
																				
					//
					//reinit
					//
					offset = "";
					protocol = "";
					local_address = "";
					foreign_address = "";
					state = "";
					PID = "";
					owner = "";
					created = "";
					
					//
					//split
					//
					array = line.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					for(String token : array)
					{
						if(token == null || token.trim().equals(""))
							continue;												
						
						token = token.trim();
						
						if(offset.equals(""))
							offset = token;
						else if(protocol.equals(""))
							protocol = token;
						else if(local_address.equals(""))
							local_address = token;
						else if(foreign_address.equals(""))
							foreign_address = token;
						else if(PID.equals(""))
						{
							//test if we have a PID or state
							try	
							{	
								PID = ""+Integer.parseInt(token);									
							}	
							catch(Exception e)
							{
								state = token;
							}
						}
						else if(owner.equals(""))
							owner = token;
						else if(token.contains("-") || token.contains(":") || token.contains("UTC"))
							created = created + " " + token;
						else
							owner = owner + " " + token;																		
						
					}
					
					if(lower.contains("no suitable address") || lower.contains("tried to open")  || lower.contains("need base")  || lower.contains("incompatible profile") || lower.contains("no base address")  || (lower.contains("invalid") && lower.contains("signature") ) || (lower.contains("valid") && lower.contains("found") )  || (lower.contains("address") && lower.contains("space") )  || (lower.contains("no") && lower.contains("valid") ) || (lower.contains("no") && lower.contains("signature") ))
						continue;
										
					//
					//normalize
					//
					tree_key = "Protocol: " + protocol + "\t" + "Local Address: " + local_address + "\t" + "Foreign Address" + "\t" + foreign_address + "\t" + "State: " + state + "\t" + "PID: " + PID + "\t" + "Owner: " + owner  + "\t" + "Created: " + created + "\t" + "Offset: " + offset + "\t"; 
					
					//
					//determine if we have seen this key before
					//
					if(this.process_pre.output.contains(line) || this.process_pre.output.contains(trim))
					{
						if(indicate_duplicate_entries)
							this.tree_analysis.put("[ = ] \t" + tree_key, "");
						
						continue;
					}
					
					//otw, add!
					this.tree_analysis.put("[ + ] \t" + tree_key, "");					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for POST analysis	
			
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//		
			if(include_removed_entries)
			{
				for(String pre_key : process_pre.output)
				{
					if(pre_key == null)
						continue;
					
					if(pre_key.trim().equals(""))
						continue;
					
					if(process_post.output.contains(pre_key))
						continue;//this is an [ = ] condition btw ;-)
					
					lower = pre_key.toLowerCase().trim();
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(pre_key.contains("no suitable address") || pre_key.contains("tried to open")  || pre_key.contains("need base")  || pre_key.contains("incompatible profile") || pre_key.contains("no base address")  || (pre_key.contains("invalid") && pre_key.contains("signature") ) || (pre_key.contains("valid") && pre_key.contains("found") )  || (pre_key.contains("address") && pre_key.contains("space") )  || (pre_key.contains("no") && pre_key.contains("valid") ) || (pre_key.contains("no") && pre_key.contains("signature") ))
						continue;
					
					//
					//reinit
					//
					offset = "";
					protocol = "";
					local_address = "";
					foreign_address = "";
					state = "";
					PID = "";
					owner = "";
					created = "";
					
					
					//
					//split
					//
					array = pre_key.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					for(String token : array)
					{
						if(token == null || token.trim().equals(""))
							continue;												
						
						token = token.trim();
						
						if(offset.equals(""))
							offset = token;
						else if(protocol.equals(""))
							protocol = token;
						else if(local_address.equals(""))
							local_address = token;
						else if(foreign_address.equals(""))
							foreign_address = token;
						else if(PID.equals(""))
						{
							//test if we have a PID or state
							try	
							{	
								PID = ""+Integer.parseInt(token);									
							}	
							catch(Exception e)
							{
								state = token;
							}
						}
						else if(owner.equals(""))
							owner = token;
						else if(token.contains("-") || token.contains(":") || token.contains("UTC"))
							created = created + " " + token;
						else
							owner = owner + " " + token;																		
						
					}
					
										
					//
					//normalize
					//
					tree_key = "Protocol: " + protocol + "\t" + "Local Address: " + local_address + "\t" + "Foreign Address" + "\t" + foreign_address + "\t" + "State: " + state + "\t" + "PID: " + PID + "\t" + "Owner: " + owner  + "\t" + "Created: " + created + "\t" + "Offset: " + offset + "\t";					
					
					this.tree_analysis.put("[ - ] \t" + tree_key, "");														
					
				}
			}
						
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_netscan", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	
	private boolean analyze_results_key_using_tree(boolean include_removed_entries, boolean indicate_duplicate_entries)
	{
		try
		{
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			String lower = "";
			String trim = "";
			String key = "";
			String value = "";
			String [] array = null;
			String tree_key = "";
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
					
					
					//
					//dismiss
					//
					if(lower.contains("offset") && lower.contains("name") && lower.contains("base") && lower.contains("size"))
						continue;	
																				
					//
					//reinit
					//
					key = "";
					value = "";
					
					//
					//split
					//
					array = line.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					for(String token : array)
					{
						if(token == null || token.trim().equals(""))
							continue;
						
						token = token.trim();
						
						if(token.startsWith("0x"))
							continue;
						
						if(key.equals(""))
							key = token;
						else if(value.equals(""))
							value = value + " " + token;
					}
					
					value = value.trim();
					
					//ensure we have proper value
					if(value.equals(""))
						continue;
					
					//
					//normalize
					//
					key = "Name: " + key;
					value = "File: " +  value;
					
					tree_key = key + " " + value;
					
					//
					//determine if we have seen this key before
					//
					if(this.process_pre.output.contains(line) || this.process_pre.output.contains(trim))
					{
						if(indicate_duplicate_entries)
							this.tree_analysis.put("[ = ] \t" + tree_key, line);
						
						continue;
					}
					
					//otw, add!
					this.tree_analysis.put("[ + ] \t" + tree_key, line);					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for POST analysis	
			
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//		
			if(include_removed_entries)
			{
				for(String pre_key : process_pre.output)
				{
					if(pre_key == null)
						continue;
					
					if(pre_key.trim().equals(""))
						continue;
					
					if(process_post.output.contains(pre_key))
						continue;//this is an [ = ] condition btw ;-)
					
					else//otw, its a key that existed in pre but is not found in post
						this.tree_analysis.put("[ - ] \t" + pre_key, "");														
					
				}
			}
						
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_key_using_tree", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	
	private boolean analyze_results_sockets_sockscan(boolean include_removed_entries, boolean indicate_duplicate_entries)
	{
		try
		{
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			String lower = "";
			String trim = "";
			String key = "";
			String value = "";
			String [] array = null;
			String tree_key = "";
			
			String offset = "";
			String pid = "";
			String port = "";
			String proto_val = "";
			String protocol = "";
			String address = "";
			String create_time = "";
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(trim.startsWith("---"))
						continue;	
					
					
					//
					//dismiss
					//
					if(lower.contains("offset") && lower.contains("pid") && lower.contains("port") && lower.contains("proto"))
						continue;	
																				
					//
					//reinit
					//
					key = "";
					value = "";
					
					offset = "";
					pid = "";
					port = "";
					proto_val = "";
					protocol = "";
					address = "";
					create_time = "";
					
					//
					//split
					//
					array = line.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					for(String token : array)
					{
						if(token == null || token.trim().equals(""))
							continue;
						
						token = token.trim();
						
						if(offset.equals(""))
							offset = token;
						else if(pid.equals(""))
							pid = token;
						else if(port.equals(""))
							port = token;
						else if(proto_val.equals(""))
							proto_val = token;
						else if(protocol.equals(""))
							protocol = token;
						else if(address.equals(""))
							address = token;
						else 
							create_time = create_time + " " + token;
						
					}
					
					create_time = create_time.trim();
					
					
					//
					//normalize
					//					
					tree_key = "Address: " + address + ":" + port + " \tPID: " + pid + " \tProtocol: " + protocol + " [" + proto_val + "] " + " \tCreate Time: " + create_time + " \tOffset: " + offset;
					
					//
					//determine if we have seen this key before
					//
					if(this.process_pre.output.contains(line) || this.process_pre.output.contains(trim))
					{
						if(indicate_duplicate_entries)
							this.tree_analysis.put("[ = ] \t" + tree_key, "");
						
						continue;
					}
					
					//otw, add!
					this.tree_analysis.put("[ + ] \t" + tree_key, "");					
					
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for POST analysis	
			
			
			//
			// Analyze the [-] condition where a key existed in pre but was not found in post
			//		
			if(include_removed_entries)
			{
				for(String pre_key : process_pre.output)
				{
					if(pre_key == null)
						continue;
					
					if(pre_key.trim().equals(""))
						continue;
					
					if(pre_key.trim().startsWith("---"))
						continue;
					
					if(process_post.output.contains(pre_key))
						continue;//this is an [ = ] condition btw ;-)
					
					offset = "";
					pid = "";
					port = "";
					proto_val = "";
					protocol = "";
					address = "";
					create_time = "";
					
					//
					//split
					//
					array = pre_key.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					for(String token : array)
					{
						if(token == null || token.trim().equals(""))
							continue;
						
						token = token.trim();
						
						if(offset.equals(""))
							offset = token;
						else if(pid.equals(""))
							pid = token;
						else if(port.equals(""))
							port = token;
						else if(proto_val.equals(""))
							proto_val = token;
						else if(protocol.equals(""))
							protocol = token;
						else if(address.equals(""))
							address = token;
						else 
							create_time = create_time + " " + token;
						
					}
					
					create_time = create_time.trim();
					
					
					//
					//normalize
					//					
					tree_key = "Address: " + address + ":" + port + " \tPID: " + pid + " \tProtocol: " + protocol + " [" + proto_val + "] " + " \tCreate Time: " + create_time + " \tOffset: " + offset;
					
					
					//otw, its a key that existed in pre but is not found in post
					this.tree_analysis.put("[ - ] \t" + tree_key, "");														
					
				}
			}
						
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_sockets_sockscan", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	private boolean analyze_results_timeliner(boolean include_removed_entries, boolean indicate_duplicate_entries)
	{
		try
		{
			//
			//NOTE: to analyze, just update how the key is procurred, and the rest should be fine.
			//you must update the key in both places below - SoloSonya@Carpenter1010
			//
			
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			//
			//init
			//
			String lower = "";
			String temp = "";
			
			LinkedList<String> list_pre = new LinkedList<String>();
			LinkedList<String> list_post = new LinkedList<String>();
			
			
			//
			//PRE
			//
			
			for(String line : process_pre.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					line = line.replaceAll("\t", " ").trim();
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					if(line.startsWith("*"))
						continue;
					
					//assume every line starts with a date, if not, then append it to the previous line
					try
					{
						//test if it appears we have a date first
						Integer.parseInt(lower.substring(0, 4));
						
						//success! add the full entry
						list_pre.add(line);
					}
					
					catch(Exception ee)
					{
						//add to previous entry
						temp = list_pre.removeLast() + " " + line;
						
						list_pre.add(temp);												
					}
					
					
				}//end overall try
				catch(Exception e)
				{
					continue;
				}
				
			}//end for loop for PRE analysis
			
			
			//
			//POST
			//
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					line = line.replaceAll("\t", " ").trim();
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug") && lower.contains("error"))
						continue;
					
					if(line.startsWith("---"))
						continue;
					
					if(line.startsWith("*"))
						continue;
					
					//assume every line starts with a date, if not, then append it to the previous line
					try
					{
						//test if it appears we have a date first
						Integer.parseInt(lower.substring(0, 4));
						
						//success! add the full entry
						list_post.add(line);
					}
					
					catch(Exception ee)
					{
						//add to previous entry
						temp = list_post.removeLast() + " " + line;
						
						list_post.add(temp);												
					}
					
					
				}//end overall try
				catch(Exception e)
				{
					continue;
				}
				
			}//end for loop for PRE analysis
			
			//
			//sort the arrays
			//
			Collections.sort(list_pre);
			Collections.sort(list_post);
			
			//driver.write_list_to_file(list_post, "post", ".txt", true);
			//driver.write_list_to_file(list_pre, "pre", ".txt",  true);
			
			//
			//analyze
			//
			for(String entry : list_post)
			{
				//substring to the first "|" which gets us beyond the date specification
				if(list_pre.contains(entry))
				{
					if(indicate_duplicate_entries)
						this.tree_analysis.put("[ = ] \t" + entry, "");
				}
				
				else//new entry
					this.tree_analysis.put("[ + ] \t" + entry, "");
			}
			
			if(include_removed_entries)
			{
				for(String entry_pre : list_pre)
				{
					if(!list_post.contains(entry_pre))
						this.tree_analysis.put("[ - ] \t" + entry_pre, "");
				}
			}
			
			
			
			
			
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_timeliner", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	
	
	
	
	
	private boolean analyze_results_userassist(boolean include_removed_entries, boolean indicate_duplicate_entries)
	{
		try
		{
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			String lower = "";
			String trim = "";
			String registry = "";
			String path = "";
			
					
			
			TreeMap<String, String> tree_keys_pre = new TreeMap<String, String>();
			TreeMap<String, String> tree_keys_post = new TreeMap<String, String>();
			
			for(String line : process_pre.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
					
					if(lower.startsWith("registry"))
						registry = line;
					else if(lower.startsWith("path"))
					{
						path = line;
						
						tree_keys_pre.put(registry + "\t " + path, "");
						
						registry = "";
						path = "";
					}
					else if(lower.startsWith("reg_binary") && lower.contains("\\"))
					{
						tree_keys_pre.put(line, "");
					}
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for PRE key/value pair population	
			
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
					
					if(lower.startsWith("registry"))
						registry = line;
					else if(lower.startsWith("path"))
					{
						path = line;
						
						tree_keys_post.put(registry + "\t " + path, "");
						
						registry = "";
						path = "";
					}
					else if(lower.startsWith("reg_binary") && lower.contains("\\"))
					{
						tree_keys_post.put(line, "");
					}
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for POST key/value pair population	
			
			//
			//ANALYSIS
			//
			for(String key_entry : tree_keys_post.keySet())
			{
				if(tree_keys_pre.containsKey(key_entry))
				{
					if(indicate_duplicate_entries)
						this.tree_analysis.put("[ = ] \t" + key_entry, "");
				}
				
				else//new entry!
					this.tree_analysis.put("[ + ] \t" + key_entry, "");
			}
			
			//
			//removed entries
			//
			if(include_removed_entries)
			{
				for(String key_entry : tree_keys_pre.keySet())
				{
					if(!tree_keys_post.containsKey(key_entry) && !tree_analysis.containsKey(key_entry))
						this.tree_analysis.put("[ - ] \t" + key_entry, "");	
					//else if(tree_keys_post.containsKey(key_entry) && tree_keys_post.get(key_entry) != null && tree_keys_pre.get(key_entry) != null && !tree_keys_pre.get(key_entry).equalsIgnoreCase(tree_keys_post.get(key_entry)))
						//this.tree_analysis.put("[ <> ] \t" + key_entry, tree_keys_pre.get(key_entry));
				}
			}
			
			//store 
						
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_userassist", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	

	private boolean analyze_results_handles(boolean include_removed_entries, boolean indicate_duplicate_entries)
	{
		try
		{
			
			//
			//validate
			//
			if(this.process_pre == null || this.process_pre.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			if(this.process_post == null || this.process_post.output == null)
			{
				sop("NOTE: Output list for plugin [" + this.plugin_text + "] is null");
				this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
				return false;
			}
			
			String lower = "";
			String trim = "";
			
			String pid = "";
			String type = "";
			String details = "";
			
			String offset = "";
			String handle = "";
			String access = "";
			
			String [] array = null;
			
			TreeMap<String, String> tree_keys_pre = new TreeMap<String, String>();
			TreeMap<String, String> tree_keys_post = new TreeMap<String, String>();
			
			for(String line : process_pre.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
					
					if(lower.contains("offset") && lower.contains("pid") && lower.contains("handle") && lower.contains("access"))
						continue;
					
					
					array = line.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					for(String token : array)
					{
						if(token == null)
							continue;
						
						token = token.trim();
						
						if(token.equals(""))
							continue;
						
						if(offset.equals(""))
							offset = token;
						else if(pid.equals(""))
							pid = token;
						else if(handle.equals(""))
							handle = token;
						else if(access.equals(""))
							access = token;
						else if(type.equals(""))
							type = token;
						else 
							details = details + " " + token;						
					}
					
					details = details.trim();
					
					if(details.equals(""))
						continue;										
					
					tree_keys_pre.put("PID: " + pid + "\t Type: " + type + "\t Details: " + details, "Offset: " + offset + "\t Handle: " + handle + "\t Access: " + access);
					
					pid = "";
					type = "";
					details = "";

					offset = "";
					handle = "";
					access = "";
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for PRE key/value pair population	
			
			
			for(String line : process_post.output)
			{
				try
				{
					if(line == null)
						continue;	
					
					trim = line.trim();
					
					if(trim.equals(""))
						continue;
					
					if(line.startsWith("#"))
						continue;
					
					lower = line.toLowerCase().trim();
									
					if(lower.contains("volatility") && lower.contains("foundation"))
						continue;
					
					if(lower.contains("volatility") && lower.contains("debug"))
						continue;
					
					if(line.startsWith("---"))
						continue;	
					
					if(lower.contains("offset") && lower.contains("pid") && lower.contains("handle") && lower.contains("access"))
						continue;
					
					
					array = line.split(" ");
					
					if(array == null || array.length < 1)
						continue;
					
					for(String token : array)
					{
						if(token == null)
							continue;
						
						token = token.trim();
						
						if(token.equals(""))
							continue;
						
						if(offset.equals(""))
							offset = token;
						else if(pid.equals(""))
							pid = token;
						else if(handle.equals(""))
							handle = token;
						else if(access.equals(""))
							access = token;
						else if(type.equals(""))
							type = token;
						else 
							details = details + " " + token;						
					}
					
					details = details.trim();
					
					if(details.equals(""))
						continue;										
					
					tree_keys_post.put("PID: " + pid + "\t Type: " + type + "\t Details: " + details, "Offset: " + offset + "\t Handle: " + handle + "\t Access: " + access);
					
					pid = "";
					type = "";
					details = "";

					offset = "";
					handle = "";
					access = "";
					
				}//end try
				catch(Exception e)
				{
					continue;
				}								
				
			}//end for loop for POST key/value pair population	
			
			//
			//ANALYSIS
			//
			for(String key_entry : tree_keys_post.keySet())
			{
				if(tree_keys_pre.containsKey(key_entry))
				{
					if(indicate_duplicate_entries)
						this.tree_analysis.put("[ = ] \t" + key_entry, "[PRE]: " + tree_keys_pre.get(key_entry) + "\t [POST]: " + tree_keys_post.get(key_entry));
				}
				
				else//new entry!
					this.tree_analysis.put("[ + ] \t" + key_entry, tree_keys_post.get(key_entry));
			}
			
			//
			//removed entries
			//
			if(include_removed_entries)
			{
				for(String key_entry : tree_keys_pre.keySet())
				{
					if(!tree_keys_post.containsKey(key_entry) && !tree_analysis.containsKey(key_entry))
						this.tree_analysis.put("[ - ] \t" + key_entry, tree_keys_pre.get(key_entry));
				}
			}
			
			//store 
						
			sop("Analysis complete on plugin [" + this.plugin.plugin_name + "]. Results stored and ready to be written to disk.");
			
			this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_results_handles", e);
		}
		
		this.EXECUTION_PLUGIN_PAIR_COMPLETE = true;
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
