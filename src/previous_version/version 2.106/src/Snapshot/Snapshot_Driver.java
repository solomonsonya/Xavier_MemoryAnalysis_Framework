/**
 * Main driver for the snapshot analysis.  This class handles calling the appropriate plugins and once they are complete, it runs the analysis
 * 
 * @author Solomon Sonya
 */

package Snapshot;

import Driver.*;
import Interface.*;
import java.io.*;
import java.util.LinkedList;
import java.util.TreeMap;

import javax.swing.*;
import Plugin.*;
import java.awt.event.*;

public class Snapshot_Driver extends Thread implements Runnable, ActionListener
{
	public static final String myClassName = "Snapshot_Driver";
	public static volatile Driver driver = new Driver();
	
	public static final boolean INCLUDE_PLUGIN_HEADER = true;
	
	public volatile FileAttributeData file_attr_memory_image_1 = null;
	public volatile FileAttributeData file_attr_memory_image_2 = null;
	
	public volatile File fleImage1 = null;
	public volatile File fleImage2 = null;
	
	public volatile String profile1 = "";
	public volatile String profile2 = "";
	
	public static volatile long SNAPSHOT_INDEX = 0;
	
	public volatile boolean EXECUTION_COMPLETE = false;

	
	public String snapshot_name = "Snapshot [" + SNAPSHOT_INDEX++ + "]";
	public JTextArea_Solomon jtaConsole = new JTextArea_Solomon("", true, snapshot_name, true);
	
	public String TIME_STAMP = driver.get_time_stamp("_");
	public String TIME_STAMP_HYPHEN_DELIMITED = driver.get_time_stamp("-");
	public File fleSnapShotTopFolder = new File(Interface.path_fle_analysis_directory + "_snapshot_" + TIME_STAMP);
	public volatile String path_snapshot_top_folder = "";
	
	FilePrintWriter pwOutput = null;
	
	public volatile Timer tmr = null;
	public volatile boolean handle_interrupt = true;
	public volatile boolean SNAPSHOT_EXECUTION_COMPLETE = false;
	
	public volatile LinkedList<Snapshot_Plugin> list_plugins = new LinkedList<Snapshot_Plugin>();
	
	public volatile LinkedList<String> list_attempted_PID_to_dump = new LinkedList<String>();
	
	public volatile Snapshot_Plugin snapshot_pslist = null;
	public volatile Snapshot_Plugin snapshot_psscan = null;
	public volatile Snapshot_Plugin snapshot_pstree = null;
	
	public Snapshot_Driver(File fleImage_1, String profile_1, File fleImage_2, String profile_2)
	{
		try
		{
			fleImage1 = fleImage_1;
			fleImage2 = fleImage_2;
			
			profile1 = profile_1;
			profile2 = profile_2;
						
			if(fleImage1 != null && fleImage1.exists() && fleImage1.isFile() && fleImage2 != null && fleImage2.exists() && fleImage2.isFile() && profile1 != null && !profile1.trim().equals("") && profile2 != null && !profile2.trim().equals(""))
			{
				this.start();
			}
			
			else
			{
				directive("\nUnable to commence snapshot analysis. Invalid object received:");
				directive("\tSnapshot Image File 1 [PRE]: " + fleImage1);
				directive("\tSnapshot Image Profile 1 [PRE]: " + profile1);
				directive("\tSnapshot Image File 2 [POST]: " + fleImage2);
				directive("\tSnapshot Image Profile 2 [POST]: " + profile2);
				
			}
			
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
			if(Interface.fle_volatility == null || !Interface.fle_volatility.exists() || !Interface.fle_volatility.isFile())
			{
				driver.jop("* * * ERROR! You must select a valid volatility executable binary first! * * *");
			}
						
			
			else if(fleImage1 != null && fleImage1.exists() && fleImage1.isFile() && fleImage2 != null && fleImage2.exists() && fleImage2.isFile() && profile1 != null && !profile1.trim().equals("") && profile2 != null && !profile2.trim().equals(""))
			{
				configure_environment();
				execute_plugins();
				
				
				
				
				this.tmr = new Timer(3000, this);
				tmr.start();
			}
			
			else
			{
				directive("\n*Unable to commence snapshot analysis. Invalid object received:");
				directive("\t*Path to volatility: " + Interface.fle_volatility);
				directive("\t*Snapshot Image File 1 [PRE]: " + fleImage1);
				directive("\t*Snapshot Image Profile 1 [PRE]: " + profile1);
				directive("\t*Snapshot Image File 2 [POST]: " + fleImage2);
				directive("\t*Snapshot Image Profile 2 [POST]: " + profile2);
				
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean configure_environment()
	{
		try
		{
			//set the File attributes
			file_attr_memory_image_1 = new FileAttributeData(this.fleImage1, true, true);
			file_attr_memory_image_2 = new FileAttributeData(this.fleImage2, true, true);
			
			if(!fleSnapShotTopFolder.exists() || !fleSnapShotTopFolder.isDirectory())
				fleSnapShotTopFolder.mkdirs();			
			
			this.path_snapshot_top_folder = fleSnapShotTopFolder.getCanonicalPath().trim();
									
			if(!path_snapshot_top_folder.endsWith(File.separator))
				path_snapshot_top_folder = path_snapshot_top_folder + File.separator;
			
			pwOutput = new FilePrintWriter(path_snapshot_top_folder + "snapshot_analysis_" + TIME_STAMP + ".txt");
			
			this.write_process_header(pwOutput);
			
			sop("\nExecuting Snapshot Analysis.");
			sop("\t[+] Means a new added entry found in the POST image but was not present in the PRE image");
			sop("\t[-] Means an entry found in the PRE image but was not present in POST image");
			sop("\t[=] Means an entry found both in PRE and POST memory images");
			
			sop("\nWriting Snapshot Analysis data to file: " + pwOutput.fle.getCanonicalPath());
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "configure_environment", e);
		}
		
		return false;
	}
	
	public boolean execute_plugins()
	{
		try
		{
			//
			//pslist
			//
			snapshot_pslist = new Snapshot_Plugin(this, "pslist", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_pslist.analyze_pslist = true;
			snapshot_pslist.start();
			list_plugins.add(snapshot_pslist);
			
			//
			//psscan
			//
			snapshot_psscan = new Snapshot_Plugin(this, "psscan", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_psscan.analyze_psscan = true;
			snapshot_psscan.start();
			list_plugins.add(snapshot_psscan);
					
			//
			//pstree
			//
			snapshot_pstree = new Snapshot_Plugin(this, "pstree", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_pstree.analyze_tree = true;
			snapshot_pstree.start();
			list_plugins.add(snapshot_pstree);
			
			//
			//sessions
			//
			Snapshot_Plugin snapshot_sessions = new Snapshot_Plugin(this, "sessions", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_sessions.analyze_sessions = true;
			snapshot_sessions.start();
			list_plugins.add(snapshot_sessions);
			
			//
			//connections
			//
			Snapshot_Plugin snapshot_connections = new Snapshot_Plugin(this, "connections", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_connections.analyze_connections = true;
			snapshot_connections.start();
			list_plugins.add(snapshot_connections);
			
			//
			//connscan
			//
			Snapshot_Plugin snapshot_connscan = new Snapshot_Plugin(this, "connscan", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_connscan.analyze_connscan = true;
			snapshot_connscan.start();
			list_plugins.add(snapshot_connscan);
			
			//
			//sockets
			//
			Snapshot_Plugin snapshot_sockets = new Snapshot_Plugin(this, "sockets", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_sockets.analyze_sockets = true;
			snapshot_sockets.start();
			list_plugins.add(snapshot_sockets);
			
			//
			//sockscan
			//
			Snapshot_Plugin snapshot_sockscan = new Snapshot_Plugin(this, "sockscan", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_sockscan.analyze_sockscan = true;
			snapshot_sockscan.start();
			list_plugins.add(snapshot_sockscan);
			
			//
			//netscan
			//
			Snapshot_Plugin snapshot_netscan = new Snapshot_Plugin(this, "netscan", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_netscan.analyze_netscan = true;
			snapshot_netscan.start();
			list_plugins.add(snapshot_netscan);
			
			
			
			
			
			//
			//cmdline
			//
			Snapshot_Plugin snapshot_cmdline = new Snapshot_Plugin(this, "cmdline", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_cmdline.analyze_cmdline = true;
			snapshot_cmdline.start();
			list_plugins.add(snapshot_cmdline);
			
			//
			//consoles
			//
			/*** * * special note: we only include the additions because this can be very messy!*/
			Snapshot_Plugin snapshot_consoles = new Snapshot_Plugin(this, "consoles", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_consoles.analyze_consoles = true;
			snapshot_consoles.start();
			list_plugins.add(snapshot_consoles);
			
			
			//
			//hashdump
			//
			Snapshot_Plugin snapshot_hashdump = new Snapshot_Plugin(this, "hashdump", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_hashdump.analyze_hashdump = true;
			snapshot_hashdump.start();
			list_plugins.add(snapshot_hashdump);		
			
			//
			//mftparser
			//
			Snapshot_Plugin snapshot_mftparser = new Snapshot_Plugin(this, "mftparser", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_mftparser.analyze_mftparser = true;
			snapshot_mftparser.start();
			list_plugins.add(snapshot_mftparser);
			
			//
			//timeliner
			//
			/**NOTE: This takes a long time to finish!*/
			Snapshot_Plugin snapshot_timeliner = new Snapshot_Plugin(this, "timeliner", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_timeliner.analyze_timeliner = true;
			snapshot_timeliner.start();
			list_plugins.add(snapshot_timeliner);
			
			//
			//filescan
			//
			Snapshot_Plugin snapshot_filescan = new Snapshot_Plugin(this, "filescan", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_filescan.analyze_filescan = true;
			snapshot_filescan.start();
			list_plugins.add(snapshot_filescan);
			
			//
			//shimcache
			//
			Snapshot_Plugin snapshot_shimcache = new Snapshot_Plugin(this, "shimcache", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_shimcache.analyze_shimcache = true;
			snapshot_shimcache.start();
			list_plugins.add(snapshot_shimcache);					
			
			//
			//shellbags
			//
			Snapshot_Plugin snapshot_shellbags = new Snapshot_Plugin(this, "shellbags", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_shellbags.analyze_shellbags = true;
			snapshot_shellbags.start();
			list_plugins.add(snapshot_shellbags);									
			
			//
			//deskscan
			//
			Snapshot_Plugin snapshot_deskscan = new Snapshot_Plugin(this, "deskscan", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_deskscan.analyze_deskscan = true;
			snapshot_deskscan.start();
			list_plugins.add(snapshot_deskscan);
			
			//
			//dlllist
			//
			Snapshot_Plugin snapshot_dlllist = new Snapshot_Plugin(this, "dlllist", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_dlllist.analyze_dlllist = true;
			snapshot_dlllist.start();
			list_plugins.add(snapshot_dlllist);
			
			//
			//modscan
			//
			Snapshot_Plugin snapshot_modscan = new Snapshot_Plugin(this, "modscan", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_modscan.analyze_modscan = true;
			snapshot_modscan.start();
			list_plugins.add(snapshot_modscan);
			
			//
			//modules
			//
			Snapshot_Plugin snapshot_modules = new Snapshot_Plugin(this, "modules", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_modules.analyze_modules = true;
			snapshot_modules.start();
			list_plugins.add(snapshot_modules);
			
			//
			//driverscan
			//
			Snapshot_Plugin snapshot_driverscan = new Snapshot_Plugin(this, "driverscan", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_driverscan.analyze_driverscan = true;
			snapshot_driverscan.start();
			list_plugins.add(snapshot_driverscan);
			
			//
			//svcscan
			//			
			//this one the entries would have to be analyzed better because a [+] and[-] entry may exist, but that's for instance if a service was running and is now stopped and vice versa
			Snapshot_Plugin snapshot_svcscan = new Snapshot_Plugin(this, "svcscan", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_svcscan.analyze_svcscan = true;
			snapshot_svcscan.start();
			list_plugins.add(snapshot_svcscan);
			
			
			//
			//hivelist
			//
			Snapshot_Plugin snapshot_hivelist = new Snapshot_Plugin(this, "hivelist", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_hivelist.analyze_hivelist = true;
			snapshot_hivelist.start();
			list_plugins.add(snapshot_hivelist);
			
			
			//
			//userassist
			//
			Snapshot_Plugin snapshot_userassist = new Snapshot_Plugin(this, "userassist", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_userassist.analyze_userassist = true;
			snapshot_userassist.start();
			list_plugins.add(snapshot_userassist);
			
			
			
			//
			//getservicesids
			//
			/**Halting this one for now... this plugin may take too long to analyze...*/
			/*Snapshot_Plugin snapshot_getservicesids = new Snapshot_Plugin(this, "getservicesids", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_getservicesids.analyze_getservicesids = true;
			snapshot_getservicesids.start();
			list_plugins.add(snapshot_getservicesids);*/
			
									
			//
			//iehistory
			//
			Snapshot_Plugin snapshot_iehistory = new Snapshot_Plugin(this, "iehistory", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_iehistory.analyze_iehistory = true;
			snapshot_iehistory.start();
			list_plugins.add(snapshot_iehistory);
			
			
			//
			//getsids
			//
			Snapshot_Plugin snapshot_getsids = new Snapshot_Plugin(this, "getsids", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_getsids.analyze_getsids = true;
			snapshot_getsids.start();
			list_plugins.add(snapshot_getsids);
			
			//
			//dumpcerts
			//
			/** * * note: this plugin adds processing time!*/
			/*Snapshot_Plugin snapshot_dumpcerts = new Snapshot_Plugin(this, "dumpcerts", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_dumpcerts.analyze_dumpcerts = true;
			snapshot_dumpcerts.start();
			list_plugins.add(snapshot_dumpcerts);*/
			
			
			//
			//handles
			//
			/**note: this plugin may take a very long time and max memory to analyze completely using the tree...*/
			Snapshot_Plugin snapshot_handles = new Snapshot_Plugin(this, "handles", this.fleImage1, this.profile1, this.fleImage2, this.profile2);
			snapshot_handles.analyze_handles = true;
			snapshot_handles.start();
			list_plugins.add(snapshot_handles);
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_plugins", e);
		}
		
		return false;
	}

	public boolean determine_procdump(Snapshot_Plugin snapshot)
	{
		try
		{
			if(snapshot == null || snapshot.list_added_PID == null || snapshot.list_added_PID.isEmpty())
				return false;
			
			if(!Interface.fle_volatility.exists())
				return false;
			
			String path_out_directory = this.pwOutput.fle.getCanonicalPath().trim();
			
			if(!path_out_directory.endsWith(File.separator))
				path_out_directory = path_out_directory + File.separator;
									
			//plugin
			Plugin plugin = Plugin.tree_plugins.get("procdump");
			
			if(plugin == null)
			{
				sop("Sorry, I am unable to perform procdump on the new files I found during analysis of [" + snapshot.plugin_text + "]. I cannot find the procdump plugin...");
				return false;
			}
			
			for(String PID : snapshot.list_added_PID)
			{
				if(PID == null)
					continue;
				
				PID = PID.trim();
				
				if(PID.equals(""))
					continue;
				
				if(list_attempted_PID_to_dump.contains(PID))
					continue;
				
				list_attempted_PID_to_dump.add(PID);
				
				//sop("Analyzing results from plugin [" + snapshot.plugin_text + "] - attempting to dump a newly discovered binary PID: [" + PID + "]");
				
				//extract the initial file first
				//Process_Plugin process = new Process_Plugin(plugin, plugin.plugin_name, plugin.plugin_description, this.fleImage2, file_attr_memory_image_2, Interface.fle_volatility.getName() + " -f " + "\"" + this.fleImage2 + "\"" + " " + "procdump" + " --profile=" + this.profile2 + " -p " + PID + " --dump-dir " + "\"" + path_out_directory + "\"", true, true, "pid_" + PID + "_", false);
				
				Process_Plugin process = new Process_Plugin(plugin, plugin.plugin_name, plugin.plugin_description, this.fleImage2, file_attr_memory_image_2, Interface.fle_volatility.getName() + " -f " + "\"" + this.fleImage2.getCanonicalPath() + "\"" + " procdump --profile=" + this.profile2 + " -p " + PID, true, true, "pid_" + PID + "_", true);
				

			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "determine_procdump", e);
		}
		
		return false;
	}
	
	public boolean directive(String out)
	{
		try
		{
			if(this.jtaConsole != null)
				this.jtaConsole.append(out);
			
			driver.directive(out);
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "directive", e);
		}
		
		return false;
	}
	
	
	public boolean write_process_header(FilePrintWriter pw)
	{
		try
		{
			if(pw == null)
				return false;
			
			//
			//determine the number of hash signs we'll need
			//
			int size = 0;
			
			if(Interface.investigator_name != null && Interface.investigator_name.trim().length() > 0 && Interface.investigation_description != null && Interface.investigation_description.trim().length() > 0)
			{
				if(("# Investigator Name: " + Interface.investigator_name + "\t Investigation Description: " + Interface.investigation_description).length() > size);
					size = ("# Investigator Name: " + Interface.investigator_name + "\t Investigation Description: " + Interface.investigation_description).length();
				
			}
			else if(Interface.investigation_description != null && Interface.investigation_description.trim().length() > 0)
			{
				if(("# Investigation Description: " + Interface.investigation_description).length() > size)
					size = ("# Investigation Description: " + Interface.investigation_description).length();
			}
			
			if(("# Investigation Date: " + this.TIME_STAMP_HYPHEN_DELIMITED).length() > size)
				size = ("# Investigation Date: " + this.TIME_STAMP_HYPHEN_DELIMITED).length();
			
			if(Interface.file_attr_volatility != null)
			{
				if(("# Memory Analysis Binary: " + Interface.file_attr_volatility.get_attributes("\t ")).length() > size)
					size = ("# Memory Analysis Binary: " + Interface.file_attr_volatility.get_attributes("\t ")).length();
			}
			
			/*if(Interface.fle_memory_image != null)
			{
				if(("# Memory Image Path: " + Interface.fle_memory_image.getCanonicalPath()).length() > size)
					size = ("# Memory Image Path: " + Interface.fle_memory_image.getCanonicalPath()).length();
			}
			
			if(Interface.file_attr_memory_image != null)
			{
				if(("# Memory Image Attributes: " + Interface.file_attr_memory_image.get_attributes("\t ")).length() > size)
					size = ("# Memory Image Attributes: " + Interface.file_attr_memory_image.get_attributes("\t ")).length();
			}*/
			
			
			if(("# Execution Command: " + "Xavier Snapshot Analysis").length() > size)
				size = ("# Execution Command: " + "Xavier Snapshot Analysis").length();
			
			if(("# File Image 1 [PRE] Path: " + fleImage1.getCanonicalPath()).length() > size)
				size = ("# File Image 1 [PRE]: " + fleImage1.getCanonicalPath()).length();
			
			if(("# File Image 1 [PRE] Profile: " + this.profile1).length() > size)
				size = ("# File Image 1 [PRE] Profile: " + this.profile1).length();
			
			if(("# File Image 2 [POST] Path: " + fleImage2.getCanonicalPath()).length() > size)
				size = ("# File Image 2 [POST]: " + fleImage2.getCanonicalPath()).length();
			
			if(("# File Image 2 [POST] Profile: " + this.profile2).length() > size)
				size = ("# File Image 2 [POST] Profile: " + this.profile2).length();
			
			//
			//print data
			//
			for(int i = 0; i < size+8; i ++)
				pw.print("#");
			
			pw.print("\n");
			
			if(Interface.investigator_name != null && Interface.investigator_name.trim().length() > 0 && Interface.investigation_description != null && Interface.investigation_description.trim().length() > 0)
				pw.println("# Investigator Name: " + Interface.investigator_name + "\t Investigation Description: " + Interface.investigation_description);	
			else if(Interface.investigation_description != null && Interface.investigation_description.trim().length() > 0)
				pw.println("# Investigation Description: " + Interface.investigation_description);	
			
			pw.println("# Investigation Date: " + this.TIME_STAMP_HYPHEN_DELIMITED);
			
			if(Interface.file_attr_volatility != null)
				pw.println("# Memory Analysis Binary: " + Interface.file_attr_volatility.get_attributes("\t "));
			
			/*if(Interface.fle_memory_image != null)
				pw.println("# Memory Image Path: " + Interface.fle_memory_image.getCanonicalPath());
			
			if(Interface.file_attr_memory_image != null)
				pw.println("# Memory Image Attributes: " + Interface.file_attr_memory_image.get_attributes("\t "));*/
			
			
			pw.println("# Execution Command: " + "Xavier Snapshot Analysis");
			
			pw.println("# File Image 1 [PRE] Path: " + fleImage1.getCanonicalPath());
			pw.println("# File Image 1 [PRE] Volatility Profile: " + this.profile1);
			
			if(this.file_attr_memory_image_1 != null && this.file_attr_memory_image_1.is_hashing_complete)
				pw.println("# File Image 1 [PRE] File Attributes: " + file_attr_memory_image_1.get_attributes("  "));
			
			
			pw.println("# File Image 2 [POST] Path: " + fleImage2.getCanonicalPath());
			pw.println("# File Image 2 [POST] Volatility Profile: " + this.profile2);
			
			if(this.file_attr_memory_image_2 != null && this.file_attr_memory_image_2.is_hashing_complete)
				pw.println("# File Image 2 [POST] File Attributes: " + file_attr_memory_image_2.get_attributes("  "));
			
			for(int i = 0; i < size+8; i ++)
				pw.print("#");
			
			pw.println("\n");
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "write_process_header", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	public boolean process_interrupt()
	{
		try
		{
			if(!this.handle_interrupt)
				return false;
			
			
			this.handle_interrupt = false;
			
			SNAPSHOT_EXECUTION_COMPLETE = list_plugins.getFirst().EXECUTION_PLUGIN_PAIR_COMPLETE;
			
			//loop and see when we are complete, then write the details
			for(Snapshot_Plugin snapshot : list_plugins)
			{
				SNAPSHOT_EXECUTION_COMPLETE &= snapshot.EXECUTION_PLUGIN_PAIR_COMPLETE;
			}
			
			
			
			if(SNAPSHOT_EXECUTION_COMPLETE)
			{
				try	{	this.tmr.stop();} catch(Exception e){}
				
				//
				//additional processing
				//
				if((snapshot_pslist != null && snapshot_pslist.list_added_PID != null && !snapshot_pslist.list_added_PID.isEmpty()) || (snapshot_psscan != null && snapshot_psscan.list_added_PID != null && !snapshot_psscan.list_added_PID.isEmpty()) || (snapshot_pstree != null && snapshot_pstree.list_added_PID != null && !snapshot_pstree.list_added_PID.isEmpty()) )
				{
					try
					{
						//populate list ofpids to extract
						TreeMap<String, String> tree_pids = new TreeMap<String, String>();
						
						if(snapshot_pslist != null && snapshot_pslist.list_added_PID != null && !snapshot_pslist.list_added_PID.isEmpty())
						{
							for(String pid : snapshot_pslist.list_added_PID)
								tree_pids.put(pid, pid);
						}
						
						if(snapshot_psscan != null && snapshot_psscan.list_added_PID != null && !snapshot_psscan.list_added_PID.isEmpty())
						{
							for(String pid : snapshot_psscan.list_added_PID)
								tree_pids.put(pid, pid);
						}
						
						if(snapshot_pstree != null && snapshot_pstree.list_added_PID != null && !snapshot_pstree.list_added_PID.isEmpty())
						{
							for(String pid : snapshot_pstree.list_added_PID)
								tree_pids.put(pid, pid);
						}
						
						LinkedList<String> list = new LinkedList<String>(tree_pids.values());
						
						String PIDs = list.getFirst();
						
						for(int i = 1; i < list.size(); i++)
							PIDs = PIDs + ", " + list.get(i);
						
						sop("\nI found new binary files running in memory during analysis. I will attempt to dump the following new binaries [" + PIDs + "] I discovered and place within the procdump directory for you...");
					}
					
					catch(Exception e)
					{
						sop("\nI found new binary files running in memory during analysis. I will attempt to dump the new binaries I discovered and place within the procdump directory for you...");
					}
					
					
					
					
				}
				
				determine_procdump(snapshot_pslist);
				determine_procdump(snapshot_psscan);
				determine_procdump(snapshot_pstree);
				
				
				sop("\nAll plugins have completed analysis. Moving to write results to disk...");
												
				//retain lock on semaphore
				return write_snapshot_results(list_plugins, INCLUDE_PLUGIN_HEADER);
				
			}
			
			
			this.handle_interrupt = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_interrupt", e);
		}
		
		this.handle_interrupt = true;
		return false;
	}
	
	public boolean write_snapshot_results(LinkedList<Snapshot_Plugin> list, boolean include_plugin_header)
	{
		try
		{
			if(list == null || list.isEmpty())
				return false;
			
			String header = "";
			
			for(Snapshot_Plugin snapshot : list)
			{
				this.pwOutput.println("#########################################################################################################################");
				this.pwOutput.println("# " + snapshot.plugin_text + " - " + snapshot.plugin.plugin_description); 
				this.pwOutput.println("#########################################################################################################################");
				
				if(include_plugin_header)
					header = snapshot.plugin_text + "\t ";
				else 
					header = "";
				
				if((snapshot.tree_analysis == null || snapshot.tree_analysis.isEmpty()) && (snapshot.list_analysis == null || snapshot.list_analysis.isEmpty()) )
				{
					this.pwOutput.println(" - No applicable entries stored for this plugin.\n\n"); 
					continue;
				}
				
				//
				//print specific headers
				//
				if(snapshot.plugin_text.equalsIgnoreCase("mftparser"))
					this.pwOutput.println("Plugin\tAnalysis\t" + "Creation Date" + "\t" + "Creation Time" + "\t" + "Creation UTC" + "\t" + "Modified Date" + "\t" + "Modified Time" + "\t" + "Modified UTC" + "\t" + "MFT Altered Date" + "\t" + "MFT Altered Time" + "\t" + "MFT Altered UTC" + "\t" + "Access Date" + "\t" + "Access Time" + "\t" + "Access UTC" + "\t" + "Type/Name/Path" + "\t" + "Entry Atrribute" + "\t" + "Extension");
				else if(snapshot.plugin_text.equalsIgnoreCase("shellbags"))
					this.pwOutput.println("Plugin\tAnalysis\t" + "Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path");
				
				//
				//print contents of the analysis results tree
				//
				if(snapshot.tree_analysis != null && !snapshot.tree_analysis.isEmpty())
				{
					for(String result_keys : snapshot.tree_analysis.keySet())
					{
						this.pwOutput.println(header + result_keys + "\t" + snapshot.tree_analysis.get(result_keys));
					}
				}
				
				//
				//print contents of the analysis results list
				//
				if(snapshot.list_analysis != null && !snapshot.list_analysis.isEmpty())
				{
					for(String line : snapshot.list_analysis)
					{
						this.pwOutput.println(header + line);
					}
				}
				
				
				this.pwOutput.println("\n\n");
				
				//clear stored data
				try	{	if(snapshot.tree_analysis != null) snapshot.tree_analysis.clear();}	catch(Exception e){}
				try	{	if(snapshot.list_analysis != null) snapshot.list_analysis.clear();}	catch(Exception e){}
				try	{	if(snapshot.list_keys_POST != null) snapshot.list_keys_POST.clear();}	catch(Exception e){}
			}
			
			//notify
			sop("\nCOMPLETE. All results have been written to output file: " + this.pwOutput.fle.getCanonicalPath() + "\n");
			
			System.gc();
			
			//close the file
			this.pwOutput.close();
			
			try	{	driver.open_file(this.pwOutput.fle.getParentFile().getParentFile());	}	catch(Exception e){}
			
			try	{	driver.open_file(this.pwOutput.fle);	}	catch(Exception e){}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_snapshot_results", e);
		}
		
		return false;
	}
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == this.tmr)
			{
				process_interrupt();
			}
			
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
			if(this.jtaConsole != null)
				this.jtaConsole.append(out);
			
			driver.sop(out);
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
}
