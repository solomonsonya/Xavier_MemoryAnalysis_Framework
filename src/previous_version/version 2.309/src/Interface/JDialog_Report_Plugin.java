/**
 * This Dialog class presents the user with plugin options to choose
 * 
 * @author Solomon Sonya
 */

package Interface;

import java.io.*;
import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.security.*;
import java.util.*;
import org.apache.commons.io.LineIterator;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.Timer;
import javax.swing.border.BevelBorder;
import javax.swing.border.TitledBorder;
import Driver.*;
import java.util.*;
import Plugin.*;
//import Sound.ThreadSound;
import SearchImage.SearchImage;
import Snapshot.Snapshot_Driver;
import Snapshot.Snapshot_Plugin;

public class JDialog_Report_Plugin extends JDialog implements ActionListener
{
	public static final Driver driver = new Driver();
	public static final String myClassName = "JDialog_Report_Plugin";
	public static volatile Interface parent = null;

	public volatile Timer tmr = null;
	public volatile boolean handle_interrupt = true; 
	public volatile boolean EXECUTION_COMPLETE = false;
	public volatile int completed_plugin_execution_count = 0;
	
	public static String MFT_HEADER = "";
	
	public static String EXECUTION_TIME_STAMP = driver.getTime_Specified_Hyphenated_with_seconds_using_colon(System.currentTimeMillis());

	public static volatile File fle_memory_image = null;
	public static volatile FileAttributeData file_attr_memory_image = null; 
	
	public volatile String link_name = "";
	public volatile String entry_line = "";
	public volatile String lower = "";
	public volatile int starting_index = 1;
	
	public JTabbedPane jtabbedPane = new JTabbedPane(JTabbedPane.TOP);
	
	public JPanel jpnlMain = new JPanel(new BorderLayout());
	public JTextArea_Solomon jpnlConsole  = new JTextArea_Solomon("", true, "Console", false);
	
	JPanel jpnlNorth = new JPanel(new BorderLayout());
	JPanel jpnlSouth = new JPanel(new BorderLayout());
	
	JPanel jpnlExecute = new JPanel(new BorderLayout());
		JPanel jpnlThreadSelection = new JPanel(new BorderLayout());
		JRadioButton jrbSingleThread = new JRadioButton("Single Threaded: Execute plugins serially ");
		JRadioButton jrbMultiThreaded = new JRadioButton("Multi Threaded: Execute plugins in parallel ", true);
		ButtonGroup bg = new ButtonGroup();
		JPanel jpnl_JBtnExecute = new JPanel(new GridLayout(1,1));
		JButton jbtnExecute = new JButton("Execute");
		public JLabel jlblStatus = new JLabel("0 Plugins in execution at the moment...", JLabel.CENTER);
		JPanel jpnlStatus = new JPanel(new BorderLayout());
		JButton jbtnOpenDirectory = new JButton("Open Directory");
	
	JPanel jpnlUnselected_CONTAINER = new JPanel(new BorderLayout());
	JPanel jpnlSelected_CONTAINER = new JPanel(new BorderLayout());
	
	public JLabel jlblUnselectedPluginText = new JLabel("  Unselected Plugins", JLabel.LEFT);
	public JLabel jlblSelectedPluginText = new JLabel("  Selected Plugins  ", JLabel.LEFT);
	public JLabel jlblSelected_plugins = new JLabel("0 Plugins selected...  ", JLabel.RIGHT);
	
	public JButton jbtnSelectFavorites = new JButton("Select Favorites");
	
	JPanel jpnlUnselectedPlugins = new JPanel();
	JPanel jpnlSelectedPlugins = new JPanel();
	
	JScrollPane jscrlpne_UnselectedPlugins = null;
	JScrollPane jscrlpne_SelectedPlugins = null;
	
	public volatile File fleOutputDirectory = null;
	
	public volatile int index_list = 0;
	
	public volatile LinkedList<String> list_connections = null;
	
	public volatile LinkedList<JPanel_Plugin_Analysis_Report> list_jpanel_plugins = new LinkedList<JPanel_Plugin_Analysis_Report>();
	
	/**USE FOR GUI SELECTION PLUGINS*/
	public volatile LinkedList<JPanel_Plugin_Analysis_Report> list_selected_plugins = new LinkedList<JPanel_Plugin_Analysis_Report>();
	
	/**USE FOR PLUGIN EXECUTION*/
	public volatile LinkedList<JPanel_Plugin_Analysis_Report> list_executing_plugins = new LinkedList<JPanel_Plugin_Analysis_Report>();
	
	public static volatile String [] array = null;
	
	
	
	JSplitPane_Solomon jspltpne = null;
	
	public volatile int selected_plugins_count = 0;
	public volatile int unselected_plugins_count = 0;
	
	
	
	public JDialog_Report_Plugin(Interface par)
	{
		try
		{
			parent = par;
			fle_memory_image = parent.fle_memory_image;
			file_attr_memory_image = parent.file_attr_memory_image;
			
			initialize_component();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "JDialog_Report_Plugin", e);
		}		
	}
	
	
	
	
	
	public boolean initialize_component()
	{
		try
		{
			this.setModal(false);
						
			setTitle("Select Plugins for Analysis Report");
			this.setSize(new Dimension(800,500));
			
			this.setLayout(new BorderLayout());
			
			jpnlNorth.add(BorderLayout.WEST, jlblUnselectedPluginText);
			
			jpnlNorth.add(BorderLayout.EAST, jlblSelectedPluginText);
			
			jpnlSouth.add(BorderLayout.NORTH, jlblSelected_plugins);
			
			jpnlThreadSelection.add(BorderLayout.WEST, this.jrbSingleThread);
			jpnlThreadSelection.add(BorderLayout.EAST, this.jrbMultiThreaded);
			try	{	jpnlThreadSelection.setBorder(new TitledBorder("Plugin Execution Action"));	}	catch(Exception e){}
			this.bg.add(jrbSingleThread);	this.bg.add(jrbMultiThreaded);
			jpnlExecute.add(BorderLayout.WEST, jpnlThreadSelection);
			jpnl_JBtnExecute.add(this.jbtnExecute);
			try	{	jpnl_JBtnExecute.setBorder(new TitledBorder("Execute"));	}	catch(Exception e){}
			jpnlExecute.add(BorderLayout.CENTER, jpnl_JBtnExecute);
			
			
			jpnlStatus.add(BorderLayout.NORTH, this.jlblStatus);
			jpnlStatus.add(BorderLayout.SOUTH, this.jbtnOpenDirectory);
			jbtnOpenDirectory.setVisible(false);	jbtnOpenDirectory.addActionListener(this);
			this.jpnlStatus.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
			
			jpnlExecute.add(BorderLayout.SOUTH, this.jpnlStatus);
			jpnlSouth.add(BorderLayout.SOUTH, jpnlExecute);
			jlblStatus.setVisible(false);
			jbtnExecute.addActionListener(this);
			
			
			
			
			jlblUnselectedPluginText.setFont(new Font("Tahoma", Font.BOLD, 14));
			jlblSelectedPluginText.setFont(new Font("Tahoma", Font.BOLD, 14));
			
			jpnlUnselected_CONTAINER.add(BorderLayout.SOUTH, jbtnSelectFavorites);
			jbtnSelectFavorites.addActionListener(this);
			
			jpnlUnselected_CONTAINER.add(BorderLayout.CENTER, jpnlUnselectedPlugins);
			jpnlSelected_CONTAINER.add(BorderLayout.CENTER, jpnlSelectedPlugins);
			
			this.jscrlpne_SelectedPlugins = new JScrollPane(this.jpnlSelected_CONTAINER, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			this.jscrlpne_UnselectedPlugins = new JScrollPane(this.jpnlUnselected_CONTAINER, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
				jspltpne = new JSplitPane_Solomon(JSplitPane.HORIZONTAL_SPLIT, jscrlpne_UnselectedPlugins, jscrlpne_SelectedPlugins, 260);
			
				
			jpnlMain.add(BorderLayout.NORTH, jpnlNorth);
			jpnlMain.add(BorderLayout.CENTER, jspltpne);
			jpnlMain.add(BorderLayout.SOUTH, jpnlSouth);
			
			jtabbedPane.addTab("Plugins", jpnlMain);
			jtabbedPane.addTab("Console", jpnlConsole);
			this.add(BorderLayout.CENTER, this.jtabbedPane);
			
			populate_export_btn(jpnlConsole);
			
			
			//add action listeners
			
			JPanel_Plugin_Analysis_Report jpnlPlugin = null;
			for(Plugin plugin : Plugin.list_plugins)
			{
				if(plugin == null)
					continue;
				
				jpnlPlugin = new JPanel_Plugin_Analysis_Report(plugin);
				list_jpanel_plugins.add(jpnlPlugin);
				
				jpnlPlugin.jbtnReport_Add.addActionListener(this);
				jpnlPlugin.jbtnReport_Remove.addActionListener(this);
				jpnlPlugin.jbtnReport_MoveUp.addActionListener(this);
				jpnlPlugin.jbtnReport_MoveDown.addActionListener(this);
				
				
			}
			
			//determine how many plugins are still available
			update_interface();
			
			
			
			try
			{
				this.setLocationRelativeTo(null);
			}
			catch(Exception e)
			{
				Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
				this.setLocation(dim.width/2-this.getSize().width/2, dim.height/2-this.getSize().height/2);
			}
			
			this.addWindowListener(new java.awt.event.WindowAdapter()
			{
				public void windowClosing(java.awt.event.WindowEvent e)
				{
					dispose();
				}
			});
			
			this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
			
			this.validate();
			this.setVisible(true);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_component", e);
		}
		
		return false;
	}
	
	public boolean populate_export_btn(JTextArea_Solomon jpnl)
	{
		try
		{
			jpnl.jpnlSouth.add(BorderLayout.CENTER, jpnl.jbtnExportData);
        	try	{	jpnl.jpnlSouth.setBorder(new TitledBorder("Options"));	}	catch(Exception e){}					
        	jpnl.add(BorderLayout.SOUTH, jpnl.jpnlSouth);
        	jpnl.validate();
        	jpnl.repaint();
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_export_btn", e);
		}
		
		return false;
	}
	
	public boolean update_interface()
	{
		try
		{
			//determine how many plugins are selected
			selected_plugins_count = 0;
			for(JPanel_Plugin_Analysis_Report pnl : this.list_jpanel_plugins)
			{
				if(pnl.is_selected_for_analysis_report)
					++selected_plugins_count;
			}
			
			//
			//clear panels
			//
									
			try	{	jpnlUnselectedPlugins.removeAll();} catch(Exception e){}
			try	{	jpnlSelectedPlugins.removeAll();} catch(Exception e){}
			
			unselected_plugins_count = Plugin.list_plugins.size() - selected_plugins_count;
			
			if(unselected_plugins_count > 0)
				jpnlUnselectedPlugins.setLayout(new GridLayout(unselected_plugins_count, 1, 5,5));
			
			jpnlSelectedPlugins.setLayout(new GridLayout(selected_plugins_count, 1, 5,5));
			
			for(JPanel_Plugin_Analysis_Report pnl : this.list_jpanel_plugins)
			{
				if(pnl == null)
					continue;
				
				if(pnl.is_selected_for_analysis_report)
				{
					//
					//SELECTED
					//
					//jpnlSelectedPlugins.add(plugin.jpnlReport);
					
					pnl.jbtnReport_Add.setVisible(false);
					pnl.jbtnReport_Remove.setVisible(true);
					pnl.jpnlReport_move_buttons.setVisible(true);
				}
				else
				{
					//
					//UNSELECTED
					//
					jpnlUnselectedPlugins.add(pnl.jpnlReport);
					
					pnl.jbtnReport_Add.setVisible(true);
					pnl.jbtnReport_Remove.setVisible(false);
					pnl.jpnlReport_move_buttons.setVisible(false);
				}
				
				pnl.jpnlReport.validate();
			}
			
			//add plugins in insertion order into the selected plugin list
			for(JPanel_Plugin_Analysis_Report pnl : this.list_selected_plugins)
			{
				if(pnl == null)
					continue;
				
				jpnlSelectedPlugins.add(pnl.jpnlReport);								
			}
			
			
			jpnlUnselectedPlugins.validate();
			jspltpne.validate();
			
			this.jscrlpne_SelectedPlugins.validate();
			this.jscrlpne_UnselectedPlugins.validate();
			jpnlSelectedPlugins.repaint();
			jpnlUnselectedPlugins.validate();
			
			if(selected_plugins_count < 1)
				jlblSelected_plugins.setText("  0 Plugins selected...  ");
			else if(selected_plugins_count == 1)
				jlblSelected_plugins.setText("  (1) Plugin selected out of " + Plugin.list_plugins.size() + " Plugins.  ");
			else
				jlblSelected_plugins.setText("  (" + selected_plugins_count + ") Plugins selected out of " + Plugin.list_plugins.size() + " Plugins.  ");
			
			this.validate();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "updated_interface", e);
		}
		
		return false;
	}
	
	public boolean process_interrupt()
	{
		try
		{
			if(!handle_interrupt)
				return false;
			
			handle_interrupt = false;
			
			if(list_executing_plugins.getFirst().process_plugin == null)
				EXECUTION_COMPLETE = false;
			else
				this.EXECUTION_COMPLETE = list_executing_plugins.getFirst().process_plugin.EXECUTION_COMPLETE;
			
			completed_plugin_execution_count = 0;
			
			//short circuit if a process has not finished execution yet
			for(JPanel_Plugin_Analysis_Report pnl : list_executing_plugins)
			{
				if(pnl == null)
					continue;
				
				
				
				if(pnl.process_plugin == null)
				{
					EXECUTION_COMPLETE = false; 
					break;
				}
				
				if(!EXECUTION_COMPLETE)
					break;
				
				EXECUTION_COMPLETE &= pnl.process_plugin.EXECUTION_COMPLETE;
				
				if(pnl.process_plugin.EXECUTION_COMPLETE)
					++completed_plugin_execution_count;
			}
			
			//
			//update remaining plugins count
			//
			this.jlblStatus.setText("" + (this.list_executing_plugins.size() - completed_plugin_execution_count) + " Plugin(s) remaining to complete execution...");
			
			//
			//check to stop
			//
			if(EXECUTION_COMPLETE)
			{
				//finally done!
				
				try	{	this.tmr.stop();} catch(Exception e){}
				
				this.jlblStatus.setText("COMPLETE! All " + this.list_executing_plugins.size() + " Plugin(s) executed.");
				this.jrbMultiThreaded.setEnabled(true);
				this.jrbSingleThread.setEnabled(true);
				this.jbtnExecute.setEnabled(true);
				//jbtnOpenDirectory.setVisible(true);
								
				//retain semaphore lock
				return write_analysis_report();
			}
			
			sp(".");
			
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
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{					
			if(ae.getSource() == this.jbtnExecute)
			{
				execute_plugins(this.jrbMultiThreaded.isSelected());
			} 
			
			else if(ae.getSource() == jbtnSelectFavorites)
			{
				select_favorites();						
			}
			
			else if(ae.getSource() == tmr)
			{
				process_interrupt();
			}
			
			else if(ae.getSource() == jbtnOpenDirectory && this.fleOutputDirectory != null)
			{
				driver.open_file(fleOutputDirectory);
			}
			
			else
			{
				for(JPanel_Plugin_Analysis_Report pnl : this.list_jpanel_plugins)
				{
					if(pnl == null)
						continue;
					
					if(ae.getSource() == pnl.jbtnReport_Add)
					{
						ae_Add_btn_pressed(pnl);
						System.gc();
						break;
					}
					else if(ae.getSource() == pnl.jbtnReport_Remove)
					{
						ae_Remove_btn_pressed(pnl);
						System.gc();
						break;
					}
					
					else if(ae.getSource() == pnl.jbtnReport_MoveUp)
					{
						ae_MoveUp_btn_pressed(pnl);
						System.gc();
						break;
					}
					
					else if(ae.getSource() == pnl.jbtnReport_MoveDown)
					{
						ae_MoveDown_btn_pressed(pnl);
						System.gc();
						break;
					}
				}
			}
			
			
			this.validate();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	public boolean select_favorites()
	{
		try
		{
			if(Plugin.list_favorites == null || Plugin.list_favorites.isEmpty())
			{
				driver.jop("Punt! No favorites have been identified!");
				return false;
			}
			
			//
			//Big(O) of n^2 + xe... yes, but it'll work for now. Perfect is the enemy of good :-) - Solomon Sonya
			//
			for(String name : Plugin.list_favorites)
			{
				if(name == null || name.trim().equals(""))
					continue;
				
				for(JPanel_Plugin_Analysis_Report pnl : this.list_jpanel_plugins)
				{
					if(pnl == null)
						continue;
					
					if(pnl.plugin_name.equalsIgnoreCase(name))
					{
						ae_Add_btn_pressed(pnl);
					}
				}
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "select_favorites", e);
		}
		
		return false;
		
	}
	
	public boolean execute_plugins(boolean execute_in_multithreaded)
	{
		try
		{
			handle_interrupt = true;
			jlblStatus.setToolTipText("");
			
			if(this.list_selected_plugins == null || this.list_selected_plugins.size() < 1)
			{
				driver.jop_Error("Punt! You must select at least 1 Plugin in order to continue...", false);
				return false;
			}
			
			//copy over the plugins for execution
			try	{	list_executing_plugins.clear();} catch(Exception e){ list_executing_plugins = new LinkedList<JPanel_Plugin_Analysis_Report>();}
			
			for(JPanel_Plugin_Analysis_Report pnl : this.list_selected_plugins)
			{
				if(pnl == null)
					continue;
				
				list_executing_plugins.add(pnl);
			}
			
			jlblStatus.setVisible(true);
			this.jbtnExecute.setEnabled(false);
			this.jrbSingleThread.setEnabled(false);
			this.jrbMultiThreaded.setEnabled(false);
									
			if(list_executing_plugins.size() < 2)
				jlblStatus.setText("1 Plugin in execution at the moment.");
			else
				jlblStatus.setText("" + list_executing_plugins.size() + " Plugins in execution at the moment.");

			
			//
			//run commands
			//
			
			//allow this thead and function to execute. it will block if running serially, or execute in multiple threads
			Thread thread_execution = new Thread() 
			{
			    public void run() 
			    {
			    	try 
			    	{
			    		Process_Plugin process_plugin = null;
						
						for(JPanel_Plugin_Analysis_Report pnl : list_executing_plugins)
						{				
							sop("Analysis Report - Executing plugin [" + pnl.plugin_name + "]");
							
							pnl.process_plugin = new Process_Plugin(pnl.plugin, pnl.plugin.plugin_name, pnl.plugin.plugin_description, parent.fle_memory_image, parent.file_attr_memory_image, "\"" + Interface.fle_volatility.getCanonicalPath().replace("\\", "/") + "\"" + " -f " + "\"" + fle_memory_image + "\"" + " " + pnl.plugin.plugin_name + " --profile=" + parent.PROFILE, false, true, "analysis_report", execute_in_multithreaded);
						}						
			    	} 
			    	
			    	catch(Exception e) 
			    	{
			    		//System.out.println();
			    	}
			    }  
			};

			thread_execution.start();						
					
			this.tmr = new Timer(3000, this);
			tmr.start();
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_plugins", e);
		}
		
		return false;
	}
	
	public boolean ae_MoveDown_btn_pressed(JPanel_Plugin_Analysis_Report plugin)
	{
		try
		{
			if(plugin == null)
				return false;
			
			if(this.list_selected_plugins == null || this.list_selected_plugins.size() < 2)
				return false;
			
			//get index
			index_list = 0;
			
			for(JPanel_Plugin_Analysis_Report plgn : this.list_selected_plugins)
			{
				if(plugin == plgn)
					break;
				
				++index_list;
			}
			
			//remove it from the list
			this.list_selected_plugins.remove(plugin);
			
			if(index_list+1 > this.list_selected_plugins.size())
				index_list = 0;
			else
				++index_list;
				
			this.list_selected_plugins.add(index_list, plugin);
			this.update_interface();
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "ae_MoveDown_btn_pressed", e);
		}
		
		return false;
	}
	
	
	
	public boolean ae_Add_btn_pressed(JPanel_Plugin_Analysis_Report plugin)
	{
		try
		{
			if(plugin == null)
				return false;
			
			plugin.is_selected_for_analysis_report = true;
			
			if(!list_selected_plugins.contains(plugin))
				list_selected_plugins.add(plugin);
			
			this.update_interface();
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "ae_Add_btn_pressed", e);
		}
		
		return false;
	}
	
	public boolean ae_Remove_btn_pressed(JPanel_Plugin_Analysis_Report plugin)
	{
		try
		{
			if(plugin == null)
				return false;
			
			plugin.is_selected_for_analysis_report = false;
			
			try	{	list_selected_plugins.remove(plugin);}catch(Exception e){}
			
			this.update_interface();
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "ae_Remove_btn_pressed", e);
		}
		
		return false;
	}
	
	
	
	/*public boolean ae_MoveUp_btn_pressed(Plugin plugin)
	{
		try
		{
			if(plugin == null)
				return false;
			
			if(this.list_selected_plugins == null || this.list_selected_plugins.size() < 2)
				return false;
			
			//get index
			index_list = 0;
			
			for(Plugin plgn : this.list_selected_plugins)
			{
				if(plugin == plgn)
					break;
				
				++index_list;
			}
			
			//remove it from the list
			this.list_selected_plugins.remove(plugin);
			
			if(index_list-1 < 0)
				index_list = 0;
			else
				index_list = this.list_selected_plugins.size() -1;
			
			this.list_selected_plugins.add(index_list, plugin);
			
			this.update_interface();
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "ae_MoveUp_btn_pressed", e);
		}
		
		return false;
	}*/
	
	
	public boolean ae_MoveUp_btn_pressed(JPanel_Plugin_Analysis_Report plugin)
	{
		try
		{
			if(plugin == null)
				return false;
			
			if(this.list_selected_plugins == null || this.list_selected_plugins.size() < 2)
				return false;
			
			//get index
			index_list = 0;
			
			for(JPanel_Plugin_Analysis_Report plgn : this.list_selected_plugins)
			{
				if(plugin == plgn)
					break;
				
				++index_list;
			}
			
			//remove it from the list
			this.list_selected_plugins.remove(plugin);
			
			if(index_list-1 < 0)
				index_list = this.list_selected_plugins.size() ;
			else
				--index_list;
				
			this.list_selected_plugins.add(index_list, plugin);
			this.update_interface();
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "ae_MoveUp_btn_pressed", e);
		}
		
		return false;
	}
	
	
	
	public boolean sop(String out)
	{
		try
		{
			driver.sop(out);
			
			this.jpnlConsole.append(out);
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
			this.jpnlConsole.append_sp(out);
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sp", e);
		}
		
		return false;
	}
	
	
	
	
	public boolean write_analysis_report()
	{
		try
		{
			//
			//WRITE HEADER
			//
			
			String time_stamp = driver.get_time_stamp("_");

			File fleOutput = new File(Interface.path_fle_analysis_directory + "analysis_report" + File.separator + "_" + "analysis_report" + "_" + time_stamp + ".txt");
			
			try	
			{	
				if(!fleOutput.getParentFile().exists() || !fleOutput.getParentFile().isDirectory())
					fleOutput.getParentFile().mkdirs();	
			}	 catch(Exception e){}
			
			fleOutputDirectory = fleOutput.getParentFile();
			
			//write file
			PrintWriter pwOut = new PrintWriter(new FileWriter(fleOutput), true);
			
			//create html output file
			File fleOutput_html = new File(Interface.path_fle_analysis_directory + "analysis_report" + File.separator + "_" + "analysis_report" + "_" + time_stamp + ".html");
			PrintWriter pwOut_html = new PrintWriter(new FileWriter(fleOutput_html), true);
			
			
			//
			//WRITE OVERHEAD
			//
			write_overhead(pwOut);
			write_overhead_html(pwOut_html);
			
			//
			//Write output data
			//			
			for(JPanel_Plugin_Analysis_Report pnl : list_executing_plugins)
			{
				if(pnl.plugin == null || pnl.process_plugin == null)
					continue;
				
				pwOut.println("#########################################################################################################################");
				pwOut.println("# " + pnl.plugin_name + " - " + pnl.plugin_description); 
				pwOut.println("#########################################################################################################################");
				
				
				/*pwOut_html.println("#########################################################################################################################<br>");
				pwOut_html.println("# " + pnl.plugin_name + " - " + pnl.plugin_description + "<br>"); 
				pwOut_html.println("#########################################################################################################################<br>");				
				*/							
				if(pnl.process_plugin.output == null || pnl.process_plugin.output.isEmpty())
				{
					pwOut.println(" - No applicable entries stored for this plugin.\n\n"); 
					
					pwOut_html.println(" - No applicable entries stored for this plugin.\n\n<br>");
					
					continue;
				}
				
				//
				//print specific headers
				//
				if(pnl.plugin_name.equalsIgnoreCase("mftparser"))
				{
					pwOut.println("Plugin\tAnalysis\t" + "Creation Date" + "\t" + "Creation Time" + "\t" + "Creation UTC" + "\t" + "Modified Date" + "\t" + "Modified Time" + "\t" + "Modified UTC" + "\t" + "MFT Altered Date" + "\t" + "MFT Altered Time" + "\t" + "MFT Altered UTC" + "\t" + "Access Date" + "\t" + "Access Time" + "\t" + "Access UTC" + "\t" + "Type/Name/Path" + "\t" + "Entry Atrribute" + "\t" + "Extension");
					
					//pwOut_html.println("Plugin\tAnalysis\t" + "Creation Date" + "\t" + "Creation Time" + "\t" + "Creation UTC" + "\t" + "Modified Date" + "\t" + "Modified Time" + "\t" + "Modified UTC" + "\t" + "MFT Altered Date" + "\t" + "MFT Altered Time" + "\t" + "MFT Altered UTC" + "\t" + "Access Date" + "\t" + "Access Time" + "\t" + "Access UTC" + "\t" + "Type/Name/Path" + "\t" + "Entry Atrribute" + "\t" + "Extension" + "<br>");
				}
				else if(pnl.plugin_name.equalsIgnoreCase("shellbags"))
				{
					pwOut.println("Plugin\tAnalysis\t" + "Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path");
					
					//pwOut_html.println("Plugin&nbspAnalysis&nbsp" + "Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path" + "<br>");
				}
												
				//
				//print contents of the analysis results list
				//
				for(String line : pnl.process_plugin.output)
				{
					pwOut.println(line);
				}
								
				pwOut.println("\n\n");
				
				
				if(pnl.plugin_name.equalsIgnoreCase("mftparser"))
				{
					MFT_HEADER = "Creation Date" + "\t" + "Creation Time" + "\t" + "Creation UTC" + "\t" + "Modified Date" + "\t" + "Modified Time" + "\t" + "Modified UTC" + "\t" + "MFT Altered Date" + "\t" + "MFT Altered Time" + "\t" + "MFT Altered UTC" + "\t" + "Access Date" + "\t" + "Access Time" + "\t" + "Access UTC" + "\t" + "Type/Name/Path" + "\t" + "Entry Atrribute" + "\t" + "Extension";
					
					if(pnl.process_plugin.list_mft != null && pnl.process_plugin.list_mft.size() > 0)
					{
						pwOut.println("\n#################################################################################################################");
						pwOut.println("# MFT SPECIFIC ENTRIES");
						pwOut.println("#################################################################################################################");
						pwOut.println(MFT_HEADER);
						
						for(String mft : pnl.process_plugin.list_mft)
						{
							if(mft == null || mft.trim().equals(""))
								continue;
							
							pwOut.println(mft);																												
						}
						
						pwOut.println("\n\n");
					}
					
					
					
					if(pnl.process_plugin.list_prefetch != null && pnl.process_plugin.list_prefetch.size() > 0)
					{
						pwOut.println("\n#################################################################################################################");
						pwOut.println("# PREFETCH SPECIFIC ENTRIES");
						pwOut.println("#################################################################################################################");
						pwOut.println(MFT_HEADER);						
						
						for(String prefetch : pnl.process_plugin.list_prefetch)
						{
							if(prefetch == null || prefetch.trim().equals(""))
								continue;
							
							pwOut.println(prefetch);
						}
						
						pwOut.println("\n\n");
					}
					
					//
					//TSV to print in a purty table :-)					
					//		
					write_html_table(pnl.process_plugin.list_mft, pnl.process_plugin.plugin_name, pnl.process_plugin.plugin_description + " [SPECIFIC ENTRIES]", pwOut_html, MFT_HEADER, true);
					
					write_html_table(pnl.process_plugin.list_prefetch, "prefetch", "Extracted from MFTPARSER [SPECIFIC ENTRIES]", pwOut_html, MFT_HEADER, true);
				}
				else
				{
					//write the tsv table if it exists
					write_html_table(pnl.process_plugin.output, pnl.process_plugin.plugin_name, pnl.process_plugin.plugin_description, pwOut_html, null, false);
				}
				
				//clear stored data
				try	{	if(pnl.process_plugin.output != null) pnl.process_plugin.output.clear();}	catch(Exception e){}
				
			}
			
			//
			//close
			//
			try	{	pwOut.flush();} catch(Exception e){}
			try	{	pwOut.close();} catch(Exception e){}
			
			//
			//close html file
			//
			pwOut_html.println("<br><br>" + driver.FULL_NAME + " by Solomon Sonya @Carpenter1010");
			pwOut_html.println("</html>");
			
			try	{	pwOut_html.flush();} catch(Exception e){}
			try	{	pwOut_html.close();} catch(Exception e){}
			
			//
			//write connections file
			//
			try
			{
				for(JPanel_Plugin_Analysis_Report pnl : list_executing_plugins)
				{
					if(pnl.plugin_name.equalsIgnoreCase("netscan") && pnl.process_plugin.list_connections != null && !pnl.process_plugin.list_connections.isEmpty())
						populate_connections_list(pnl.process_plugin.list_connections);
					else if(pnl.plugin_name.equalsIgnoreCase("connscan") && pnl.process_plugin.list_connections != null && !pnl.process_plugin.list_connections.isEmpty())
						populate_connections_list(pnl.process_plugin.list_connections);
					else if(pnl.plugin_name.equalsIgnoreCase("connections") && pnl.process_plugin.list_connections != null && !pnl.process_plugin.list_connections.isEmpty())
						populate_connections_list(pnl.process_plugin.list_connections);
					else if(pnl.plugin_name.equalsIgnoreCase("sockscan") && pnl.process_plugin.list_connections != null && !pnl.process_plugin.list_connections.isEmpty())
						populate_connections_list(pnl.process_plugin.list_connections);
					else if(pnl.plugin_name.equalsIgnoreCase("sockets") && pnl.process_plugin.list_connections != null && !pnl.process_plugin.list_connections.isEmpty())
						populate_connections_list(pnl.process_plugin.list_connections);
					
					if(this.list_connections != null && this.list_connections.size() > 0)
					{
						File fleOutput_connections = new File(Interface.path_fle_analysis_directory + "analysis_report" + File.separator + "_" + "foreign_connections" + "_" + time_stamp + ".txt");
						PrintWriter pwOut_connections = new PrintWriter(new FileWriter(fleOutput_connections), true);
						
						for(String connection : this.list_connections)
						{
							if(connection == null || connection.equals(""))
								continue;
							
							pwOut_connections.println(connection);
						}
						
						try	{	pwOut_connections.flush();} catch(Exception e){}
						try	{	pwOut_connections.close();} catch(Exception e){}
					}
				}
			}
			catch(Exception e){}
			
			
		
			//
			//NOTIFY
			//
			sop("\nCOMPLETE. All results have been written to output file: " + fleOutput.getCanonicalPath() + "\n");
					
			jlblStatus.setToolTipText("Analysis File: " + fleOutput.getCanonicalPath());
			
			this.jbtnOpenDirectory.setVisible(true);
			
			try	{	driver.open_file(fleOutput.getParentFile().getParentFile());	}	catch(Exception e){}

			try	{	driver.open_file(fleOutput);	}	catch(Exception e){}
			try	{	driver.open_file(fleOutput_html);	}	catch(Exception e){}

			System.gc();

			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_analysis_report", e);
		}
		
		return false;
	}
	
	public boolean populate_connections_list(LinkedList<String> list)
	{
		try
		{
			if(list == null || list.isEmpty())
				return false;
			
			if(list_connections == null)					
				list_connections = new LinkedList<String>();
			
			for(String ip : list)
			{
				if(ip == null || ip.trim().equals(""))
					continue;
				
				ip = ip.toLowerCase().trim();
				
				if(list_connections.contains(ip))
					continue;
				
				list_connections.add(ip);
			}
			
			//sort the list
			try	{	 Collections.sort(list_connections);}	catch(Exception e){}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_connections_list", e);
		}
		
		return false;
	}
	
	public boolean write_html_table(LinkedList<String> list_tsv, String name, String description, PrintWriter pw, String override_table_header_tsv, boolean print_data_as_table)
	{
		try
		{
			if(pw == null)
				return false;
			if(list_tsv == null)
				return false;
			
			if(name == null)
				name = "no name";
			
			if(description == null)
				description = "no description";
			
			if(list_tsv == null || list_tsv.isEmpty())
				return false;
			
			link_name = name.trim().replaceAll(" ", "_").replaceAll("\t", "_").trim();
			
			pw.println("<h2><b><u>" + name + "</b></u> - " + description + "</h2><hr><br>");
			
			if(print_data_as_table)
				pw.println("<table>");
			
			pw.println("<caption><u><a id=\"" + link_name + "\"> Entries </u></caption></a>\n");
			
			//
			//print heading of table
			//
			if(print_data_as_table)
			{
				starting_index = 1;
				
				if(override_table_header_tsv != null && !override_table_header_tsv.trim().equals(""))
					entry_line = override_table_header_tsv;
				else
				{
					entry_line = list_tsv.getFirst().trim();
					
					lower = entry_line.toLowerCase();
					
					if(lower.contains("volatility") && lower.contains("foundation") && lower.contains("framework"))
					{
						entry_line = list_tsv.get(1).trim();
						starting_index = 2;
					}
				}
						
				//
				//print table header
				//
				array = entry_line.split("\t");
				
				if(array != null && array.length > 0)
				{
					pw.print("<tr>\t");
					
					for(String element : array)
					{
						if(element == null || element.trim().equals(""))
							continue;
						
						pw.print("<th>" + element.trim().replaceAll(" ", "_") + "</th>" + "\t");
					}
					
					pw.print("</tr>" + "\n");
				}
					
				//
				//print table entries
				//
				for(int i = starting_index; i < list_tsv.size(); i++)
				{
					entry_line = list_tsv.get(i);
					
					if(entry_line == null)
						continue;					
					
					entry_line = entry_line.trim();
					
					if(entry_line.equals(""))
						continue;
									
					array = entry_line.split("\t");
					
					if(array == null || array.length < 1)
						continue;
					
					pw.print("\t<tr>\t");
					
					for(String element : array)
					{
						if(element == null || element.trim().equals(""))
							continue;
						
						pw.print("<td>" + element + "</td>");
					}
					
					pw.print("</tr>\t\n");								
				}
				
				pw.println("</table><br>");
			}
			
			else
			{
				for(String line : list_tsv)
				{
					if(line == null || line.trim().equals(""))
						continue;
					
					pw.println(line + "<br>");
				}
			}
			
			pw.println("<br>");
			pw.println("<a href=\"#top_analysis_report\">Back to Top</a><br><br>\n\n");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_html_table", e);
		}
		
		return false;
	}
	
	public boolean write_overhead(PrintWriter pw)
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
			
			if(("# Investigation Date: " + this.EXECUTION_TIME_STAMP).length() > size)
				size = ("# Investigation Date: " + this.EXECUTION_TIME_STAMP).length();
			
			
			if(Interface.file_attr_volatility != null)
			{
				if(("# Memory Analysis Binary: " + Interface.file_attr_volatility.get_attributes("\t ")).length() > size)
					size = ("# Memory Analysis Binary: " + Interface.file_attr_volatility.get_attributes("\t ")).length();
			}
			
			if(fle_memory_image != null)
			{
				if(("# Memory Image Path: " + fle_memory_image.getCanonicalPath()).length() > size)
					size = ("# Memory Image Path: " + fle_memory_image.getCanonicalPath()).length();
			}
			else if(Interface.fle_memory_image != null)
			{
				if(("# Memory Image Path: " + Interface.fle_memory_image.getCanonicalPath()).length() > size)
					size = ("# Memory Image Path: " + Interface.fle_memory_image.getCanonicalPath()).length();
			}
			
			if(file_attr_memory_image != null)
			{
				if(("# Memory Image Attributes: " + file_attr_memory_image.get_attributes("\t ")).length() > size)
					size = ("# Memory Image Attributes: " + file_attr_memory_image.get_attributes("\t ")).length();
			}
									
			
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
			
			pw.println("# Investigation Date: " + this.EXECUTION_TIME_STAMP);
			
			if(Interface.file_attr_volatility != null)
				pw.println("# Memory Analysis Binary: " + Interface.file_attr_volatility.get_attributes("\t "));
			
			if(fle_memory_image != null)
				pw.println("# Memory Image Path: " + fle_memory_image.getCanonicalPath());
			else if(Interface.fle_memory_image != null)
				pw.println("# Memory Image Path: " + Interface.fle_memory_image.getCanonicalPath());
			
			if(file_attr_memory_image != null)
				pw.println("# Memory Image Attributes: " + file_attr_memory_image.get_attributes("\t "));
			
			
			pw.println("# Execution Command: " + "Analysis Report");
			
			for(int i = 0; i < size+8; i ++)
				pw.print("#");
			
			pw.println("\n");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_overhead", e);
		}
		
		return false;
	}
	
	
	
	
	
	public boolean write_overhead_html(PrintWriter pw)
	{
		try
		{
			//2 things to have to do to link to a section within a webpage
			//[1] mark the section to be linked with a unique id e.g. <a id=\"top_analysis_report\">" + driver.NAME + " - Analysis Report</a> where top_analysis_report is the unique id to be linked to
			//[2] create an <a href> to hyperlink to the unique id identified above e.g. <a href=\"#top_analysis_report\">Back to Top</a> 
			
			if(pw == null)
				return false;
													
			//
			//Write html header
			//
			pw.println("<!DOCTYPE html>	<html lang=\"en\">	<head>   <meta charset=\"utf-8\">    <title>" + driver.NAME + " - Analysis Report</title>");
			pw.println("<h1> <a id=\"top_analysis_report\">" + driver.NAME + " - Analysis Report</a> </h1><hr><br>");
			pw.println("<style>  .node circle {   fill: #fff;   stroke: darkblue;   stroke-width: 1.5px; } .node text { font: 12px sans-serif; } .link {   fill: none;   stroke: #bbb;   stroke-width: 2px; } table {    font-family: arial, sans-serif;    border-collapse: collapse;    width: 100%;} td, th {    border: 1px solid #dddddd;    text-align: left;    padding: 8px;} tr:nth-child(even) {    background-color: #dddddd;} .col-container { display: table;   width: 100%;}  </style>\n");
			
		
		
			pw.print("\n");
			
			if(Interface.investigator_name != null && Interface.investigator_name.trim().length() > 0 && Interface.investigation_description != null && Interface.investigation_description.trim().length() > 0)
				pw.println("<b>Investigator Name:</b> " + Interface.investigator_name + "<br> <b>Investigation Description:</b> " + Interface.investigation_description + "<br>");	
			else if(Interface.investigation_description != null && Interface.investigation_description.trim().length() > 0)
				pw.println("<b>Investigation Description:</b> <br>" + Interface.investigation_description + "<br>");	
			
			pw.println("<b>Investigation Date</b>: " + this.EXECUTION_TIME_STAMP + "<br>");
			
			if(Interface.file_attr_volatility != null)
				pw.println("<b>Memory Analysis Binary:</b> <br> &nbsp&nbsp " + Interface.file_attr_volatility.get_attributes("<br> &nbsp&nbsp ") + "<br>");
			
			if(fle_memory_image != null)
				pw.println("<b>Memory Image Path:</b> " + fle_memory_image.getCanonicalPath() + "<br>");
			else if(Interface.fle_memory_image != null)
				pw.println("<b>Memory Image Path:</b> " + Interface.fle_memory_image.getCanonicalPath() + "<br>");
			
			if(file_attr_memory_image != null)
				pw.println("<b>Memory Image Attributes:</b> <br> &nbsp&nbsp " + file_attr_memory_image.get_attributes("<br>  &nbsp&nbsp") + "<br>");
			
			
			pw.println("<b>Execution Command:</b> " + "Analysis Report" + "<br>");
			
			pw.println("<br><hr>");
			
			//Write table of plugins included in this report
			
			int index = 0;
			
			pw.println("<br><table>");

			pw.print("\t<tr>\t");
			
			for(JPanel_Plugin_Analysis_Report pnl : this.list_selected_plugins)
			{
				link_name = pnl.plugin_name.trim().replaceAll(" ", "_").replaceAll("\t", "_").trim();
				 
				//process mftparser a bit differently because we add a prefetch after it
				if(pnl.plugin_name.equalsIgnoreCase("mftparser"))
				{
					pw.print("<td>" + "<a href=\"#" + pnl.plugin_name + "\">" + pnl.plugin_name + "</a></td>");
					
					if(++index % 5 == 0)
						pw.print("</tr>\t\n\t<tr>\t");
					
					pw.print("<td>" + "<a href=\"#" + "prefetch" + "\">" + "prefetch" + "</a></td>");
					
					if(++index % 5 == 0)
						pw.print("</tr>\t\n\t<tr>\t");
					
					continue;
				}
				
				pw.print("<td>" + "<a href=\"#" + link_name + "\">" + pnl.plugin_name + "</a></td>");
				
				if(++index % 5 == 0)
					pw.print("</tr>\t\n\t<tr>\t");
			}
			
			//close remaining row
			if(index % 5 != 0)
				pw.print("</tr>\t\n");
			
			pw.println("</table><br><hr>");
			
			pw.println("\n" + "<br>");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_overhead_html", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	

}

