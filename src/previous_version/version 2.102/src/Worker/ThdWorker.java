/**
 * This thread is just to help with repetitive tasks 
 * 
 *  @author Solomon Sonya
 */

package Worker;

import Driver.*;
import Plugin.Plugin;
import Plugin.Process_Plugin;
import Interface.*;
import java.awt.event.*;
import java.util.ConcurrentModificationException;

import javax.swing.Timer;

import Advanced_Analysis.Advanced_Analysis_Director;
import Advanced_Analysis.Analysis_Plugin._Analysis_Plugin_Super_Class;


public class ThdWorker extends Thread implements Runnable, ActionListener
{
	public static Driver driver = new Driver();
	public static final String myClassName = "ThdWorker";
	
	public volatile Timer tmrUpdate_1_SEC = null;
	public volatile Timer tmrUpdate_5_SEC = null;
	public volatile Timer tmrUpdate_10_SEC = null;	
	public volatile Timer tmrUpdate_60_SEC = null;
	public volatile Timer tmrUpdate_60_MINS = null;
	public volatile Timer tmrUpdate_10_MINS = null;
	
	public volatile boolean handle_interrupt_1_SEC = true;
	public volatile boolean handle_interrupt_5_SEC = true;
	public volatile boolean handle_interrupt_10_SEC = true;
	public volatile boolean handle_interrupt_60_SEC = true;
	public volatile boolean handle_interrupt_60_MINS = true;
	public volatile boolean handle_interrupt_10_MINS = true;
	
	public static volatile boolean refresh_jtable_protocol = false;
	public static volatile boolean refresh_jtable_resolution = false;
	
	public volatile int plugins_in_execution = 0;
	

	public volatile String plugin_names_in_execution = "";
	
	public ThdWorker()
	{
		try
		{
			this.start();
			
			
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
			//start timers
			tmrUpdate_1_SEC = new Timer(1000, this);
			tmrUpdate_1_SEC.start();
			
			tmrUpdate_5_SEC = new Timer(5000, this);
			tmrUpdate_5_SEC.start();
			
			tmrUpdate_10_SEC = new Timer(10000, this);
			tmrUpdate_10_SEC.start(); 
			
			tmrUpdate_60_SEC = new Timer(60000, this);
			tmrUpdate_60_SEC.start();
			
			tmrUpdate_10_MINS = new Timer(60000*10, this);
			tmrUpdate_10_MINS.start();
			
			tmrUpdate_60_MINS = new Timer(60000*60, this);
			tmrUpdate_60_MINS.start();
			
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
			if(ae.getSource() == this.tmrUpdate_1_SEC && this.handle_interrupt_1_SEC)
			{
				processInterrupt_1_SEC();
			}
			
			else if(ae.getSource() == this.tmrUpdate_5_SEC && this.handle_interrupt_5_SEC)
			{
				processInterrupt_5_SEC();
			}
			
			else if(ae.getSource() == this.tmrUpdate_10_SEC && this.handle_interrupt_10_SEC)
			{
				processInterrupt_10_SEC();
			}
			
			else if(ae.getSource() == this.tmrUpdate_60_SEC && this.handle_interrupt_60_SEC)
			{
				processInterrupt_60_SEC();
			}
			
			else if(ae.getSource() == this.tmrUpdate_10_MINS && this.handle_interrupt_10_MINS)
			{
				processInterrupt_10_MINS();
			}
			
			else if(ae.getSource() == this.tmrUpdate_60_MINS && this.handle_interrupt_60_MINS)
			{
				processInterrupt_60_MINS();
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	public boolean processInterrupt_1_SEC()
	{
		try
		{
			if(!handle_interrupt_1_SEC)
				return true;
			//
			//lock semaphone
			//
			handle_interrupt_1_SEC = false;
			
			//
			//WORK
			//			
			
			
			
			//
			//release semaphore
			//
			this.handle_interrupt_1_SEC = true;
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "processInterrupt_1_SEC", e);
		}
		
		//
		//release semaphore
		//
		this.handle_interrupt_1_SEC = true;
		return false;
	}
	
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	
	public boolean processInterrupt_5_SEC()
	{
		try
		{
			if(!handle_interrupt_5_SEC)
				return true;
			//
			//lock semaphone
			//
			handle_interrupt_5_SEC = false;
			
			//
			//WORK
			//	
			if(Interface.advanced_analysis_director != null && Interface.advanced_analysis_director.tree_advanced_analysis_threads != null)
			{
				
				
				plugins_in_execution = 0;
				
				if(Interface.advanced_analysis_director.process_in_execution_PSLIST)
					++plugins_in_execution;
				
				if(Interface.advanced_analysis_director.process_in_execution_PSSCAN)
					++plugins_in_execution;
				
				if(Interface.advanced_analysis_director.process_in_execution_PSTREE)
					++plugins_in_execution;
				
				if(Interface.advanced_analysis_director.process_in_execution_PSXVIEW)
					++plugins_in_execution;
				
				
				if(Interface.advanced_analysis_director.tree_advanced_analysis_threads.size() > 0)
				{
					//determine num plugins in execution 
					for(_Analysis_Plugin_Super_Class plugin : Interface.advanced_analysis_director.tree_advanced_analysis_threads.values())
					{
						try
						{
							if(plugin != null && !plugin.EXECUTION_COMPLETE)
								++plugins_in_execution;
						}
						catch(Exception e){}
					}
				}
				
				
				
				//check to return early
				if(plugins_in_execution < 1)
				{
					if(Interface.jlblStatusMessage.isVisible())
					{
						Interface.jpnlConsole.append("\nPlugin Execution Complete!");
						Interface.jlblStatusMessage.setVisible(false);
						Interface.jfrm.validate();
					}		
					
					this.handle_interrupt_5_SEC = true;
					return true;
				}
				
				Interface.jlblStatusMessage.setText(Interface.num_plugins_in_execution + "[" + plugins_in_execution + "]");
												
				try	
				{
					plugin_names_in_execution = "<html> <b>Plugins in execution:</b><br>";
					
					//check process list plugins
					if(Interface.advanced_analysis_director.process_in_execution_PSLIST)
						plugin_names_in_execution = plugin_names_in_execution + "pslist" + "<br>";
					
					if(Interface.advanced_analysis_director.process_in_execution_PSSCAN)
						plugin_names_in_execution = plugin_names_in_execution + "psscan" + "<br>";
					
					if(Interface.advanced_analysis_director.process_in_execution_PSTREE)
						plugin_names_in_execution = plugin_names_in_execution + "pstree" + "<br>";
					
					if(Interface.advanced_analysis_director.process_in_execution_PSXVIEW)
						plugin_names_in_execution = plugin_names_in_execution + "psxview" + "<br>";
					
					//iterate through the tree
					for(_Analysis_Plugin_Super_Class plugin : Interface.advanced_analysis_director.tree_advanced_analysis_threads.values())
					{
						if(plugin == null || plugin.plugin_name == null || plugin.plugin_name.trim().equals("") || plugin.EXECUTION_COMPLETE)
							continue;												
						
						if(plugin_names_in_execution.contains(plugin.get_plugin_special_identifier()))
							continue;
						else
							plugin_names_in_execution = plugin_names_in_execution + plugin.get_plugin_special_identifier() + "<br>";											
					}
					
					plugin_names_in_execution = plugin_names_in_execution + "</html>";
					
					if(!Interface.jlblStatusMessage.isVisible())
						Interface.jlblStatusMessage.setVisible(true);
					
					Interface.jlblStatusMessage.setToolTipText(plugin_names_in_execution);
					Interface.jlblStatusMessage.repaint();
					Interface.jlblStatusMessage.validate();
					
				}
				catch(Exception e)
				{
					//System.out.println("* Standby, working on plugin stats message in " + myClassName);
					//e.printStackTrace(System.out);
					this.handle_interrupt_5_SEC = true;
					return true;
				}
				
				Interface.jfrm.validate();								
			}
			else if(Interface.advanced_analysis_director == null || Interface.advanced_analysis_director.tree_advanced_analysis_threads == null || Interface.advanced_analysis_director.tree_advanced_analysis_threads.size() < 1)
			{
				if(Interface.jlblStatusMessage.isVisible())
				{
					Interface.jpnlConsole.append("\nPlugin Execution Complete!");
					Interface.jlblStatusMessage.setVisible(false);
					Interface.jfrm.validate();
				}						
			}
			
				
			
			
			//
			//release semaphore
			//
			this.handle_interrupt_5_SEC = true;
			return true;
		}
		
		catch(ConcurrentModificationException cme)
		{
			//do nothing
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "processInterrupt_5_SEC", e);
		}
		
		//
		//release semaphore
		//
		this.handle_interrupt_5_SEC = true;
		return false;
	}
	
	
		
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	
	public boolean processInterrupt_10_SEC()
	{
		try
		{
			if(!handle_interrupt_10_SEC)
				return true;
			//
			//lock semaphone
			//
			handle_interrupt_10_SEC = false;
			
			//
			//WORK
			//			
			//driver.sop("ready to process intr 10 sec... " + driver.time.getTime_Current(":", true));
			
			
			
			//
			//release semaphore
			//
			this.handle_interrupt_10_SEC = true;
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "processInterrupt_10_SEC", e);
		}
		
		//
		//release semaphore
		//
		this.handle_interrupt_10_SEC = true;
		return false;
	}
		
		
		
		
		
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
		
	public boolean processInterrupt_60_SEC()
	{
		try
		{
			if(!handle_interrupt_60_SEC)
				return true;
			//
			//lock semaphone
			//
			handle_interrupt_60_SEC = false;
			
			//
			//WORK
			//			
			
			
			
			//
			//Update OUI
			//
			//driver.driver_oui.update_MAC_Registration_Data();
			
			//
			//Update GEO
			//
			//driver.driver_geo.updateSSID();
			
			
			//
			//release semaphore
			//
			this.handle_interrupt_60_SEC = true;
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "processInterrupt_60_SEC", e);
		}
		
		//
		//release semaphore
		//
		this.handle_interrupt_60_SEC = true;
		return false;
	}	
		
		

	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////

	public boolean processInterrupt_10_MINS()
	{
		try
		{
			if(!handle_interrupt_10_MINS)
				return true;
			//
			//lock semaphone
			//
			handle_interrupt_10_MINS = false;

			//
			//WORK
			//			
			


			//
			//GC
			//
			System.gc();

			

			//
			//release semaphore
			//
			this.handle_interrupt_10_MINS = true;
			return true;
		}

		catch(Exception e)
		{
			driver.eop(myClassName, "processInterrupt_10_MINS", e);
		}

		//
		//release semaphore
		//
		this.handle_interrupt_60_MINS = true;
		return false;
	}	






	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////	
		
		
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
		
	public boolean processInterrupt_60_MINS()
	{
		try
		{
			if(!handle_interrupt_60_MINS)
				return true;
			//
			//lock semaphone
			//
			handle_interrupt_60_MINS = false;
			
			//
			//WORK
			//			
			if(driver.isLinux)
			{
				String [] cmd = new String [] {"/bin/bash", "-c", "rm -rf /tmp/*wire*"};
				Process p = Runtime.getRuntime().exec(cmd);	
			}
			if(driver.isWindows)
			{
				Process p = Runtime.getRuntime().exec("cmd.exe /C " + "del /F %temp%\\*wireshark*");
			}
			
			
			
			
			
			//
			//Update OUI
			//
			//driver.driver_oui.update_MAC_Registration_Data();
			
			//
			//Update GEO
			//
			//driver.driver_geo.updateSSID();
			
			
			//
			//release semaphore
			//
			this.handle_interrupt_60_MINS = true;
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "processInterrupt_60_SEC", e);
		}
		
		//
		//release semaphore
		//
		this.handle_interrupt_60_MINS = true;
		return false;
	}	
		
		
		
		
		
		
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////	
	
		
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////	
	
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	
}
