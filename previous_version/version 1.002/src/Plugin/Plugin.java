/**
 * @author Solomon Sonya
 */

package Plugin;


import javax.swing.*;
import java.io.*;
import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.security.*;
import java.util.*;
import org.apache.commons.io.LineIterator;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.TitledBorder;
import Driver.*;
import Interface.JTextArea_Solomon;
import Interface.*;
import java.util.*;
import java.awt.event.*;

public class Plugin extends JPanel implements ActionListener
{
	public static final String myClassName = "Plugin";
	public static volatile Driver driver = new Driver();
	
	public volatile String plugin_name = "";
	public volatile String plugin_description = "";
	
	public volatile static TreeMap<String, Plugin> tree_plugins = new TreeMap<String, Plugin>();
	
	public JPanel myJPanel = null;
	public JTabbedPane myJTabbedPane = null;
	
	public JCheckBox jcb = null;
	
	public static volatile TreeMap<String, Plugin> tree_selected_plugins = new TreeMap<String, Plugin>();
		
	public volatile JTextArea_Solomon jtaConsole = null;	
	
	
	public static final boolean clear_text_after_execution = true;
	
	public JButton jbtnOpenOutputFile = new JButton("Output File");
	public JButton jbtnOpenOutputDirectory = new JButton("Directory");
	
	/**This is set and updated at the completion of Prcess_Plugin*/
	public volatile File fleOutput = null;
	
	public static final int MAX_DESCRIPTION_LEN = 50;
	public String [] arr_description = null;
	
	public static volatile boolean plugin_selected_dumpfiles = false;
	public static volatile boolean plugin_selected_pslist = false;
	public static volatile boolean plugin_selected_psscan = false;
	public static volatile boolean plugin_selected_pstree  = false;
	public static volatile boolean need_to_notify_of_additional_plugins  = false;
	
	public static final String []arrFavoritePlugins = new String[]
			{
					"apihooks", 
					"clipboard", 
					"cmdline", 
					"cmdscan", 
					"consoles",  
					"dlllist", 
					"dumpcerts",
					"filescan", 
					"getsids", 
					"handles", 
					"hashdump", 
					"iehistory", 
					"malfind",
					//"netscan", 
					"mftparser",
					"notepad",
					"procdump",
					"pslist", 
					"psxview", 
					"sessions",
					"timeliner",
					"truecryptpassphrase", 
					"truecryptsummary", 
			};
	
	public static final String []arrPluginsToConvertOutputToTSV = new String[]
			{
					"atoms",
					"atomscan",
					"dlllist",
					"dlldump",
					"driverirp",
					"pslist", 
					"psscan", 
					"pstree", 
					"bigpools",
					"callbacks",
					"clipboard",
					"connections",
					"connscan",
					"dlllist",
					"driverscan",
					"drivermodule",
					"dumpcerts",
					"dumpfiles",
					"envars",
					"filescan",					
					"gdt",
					"gditimers",
					"handles",
					"hivelist",
					"idt",
					"impscan",
					"joblinks",
					"ldrmodules",
					"memmap",
					"messagehooks",
					"modscan",
					"modules",
					"mutantscan",
					"objtypescan",
					"pooltracker",
					"procdump",
					"privs",
					"psxview",
					"sessions",
					"shellbags",
					"shimcache",
					"sockets",
					"sockscan",
					"symlinkscan",
					"ssdt",
					"timers",
					"timeliner",
					"thrdscan",
					"netscan",
					"unloadedmodules",
					"userhandles",
					"vaddump",
					"vadwalk",
					
					
					
			};
	
	public volatile static LinkedList<String> list_favorites = null;
	public volatile static LinkedList<String> list_include_tsv_data = null;
	
	public Plugin(String PLUGIN_NAME, String PLUGIN_DESCRIPTION, JPanel jpnl_parent, JTabbedPane jtabbedpane_parent)
	{
		try
		{
			if(list_favorites == null)
			{
				list_favorites = new LinkedList<String>();
				list_favorites = populate_list(list_favorites, arrFavoritePlugins);
			}
			
			if(list_include_tsv_data == null)
			{
				list_include_tsv_data = new LinkedList<String>();
				list_include_tsv_data = populate_list(list_include_tsv_data, arrPluginsToConvertOutputToTSV);
			}
			
			if(PLUGIN_NAME != null && PLUGIN_DESCRIPTION != null)
			{
				plugin_name = PLUGIN_NAME.trim(); 
				plugin_description = PLUGIN_DESCRIPTION.trim();
				
				//driver.directive("PLUGIN: " + plugin_name + " -- " + plugin_description);
				
				if(!tree_plugins.containsKey(plugin_name + " - " + plugin_description))
					tree_plugins.put(plugin_name + " - " + plugin_description, this);				
				
				myJPanel = jpnl_parent;
				myJTabbedPane = jtabbedpane_parent;
				
				if(jpnl_parent != null)
				{
					this.setLayout(new BorderLayout());
					
					//
					//split the plugin description text into multiple lines if needed
					//					
					if(plugin_description != null && plugin_description.length() > MAX_DESCRIPTION_LEN)
					{
						LinkedList<String> list = driver.tokenize(plugin_description, MAX_DESCRIPTION_LEN);
						
						if(list == null || list.size() < 1)
							jcb = new JCheckBox("<html><b><u>" + plugin_name + "</b></u>\t" + " - " + plugin_description + "</html>", false);
						else
						{
							String plugin_name_tokenized = list.removeFirst();
							
							for(String str : list)
							{
								plugin_name_tokenized = plugin_name_tokenized + "<br>" + str;
							}
							
							jcb = new JCheckBox("<html><b><u>" + plugin_name + "</b></u>\t" + " - " + plugin_name_tokenized + "</html>", false);
						}
					}
					else
						jcb = new JCheckBox("<html><b><u>" + plugin_name + "</b></u>\t" + " - " + plugin_description + "</html>", false);
					
					this.add(BorderLayout.WEST, jcb);
					
					try	{	jcb.setFont(new Font("Helvetica", Font.PLAIN, 16));} catch(Exception e){}
					
					jcb.setToolTipText("<html><b><u>" + plugin_name + "</b></u>\t" + " - " + plugin_description + "</html>");
					
					//add self to parent
					myJPanel.add(this);
				}
			}
			
			
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - name and description", e);
		}
	}
	
	public LinkedList<String> populate_list(LinkedList<String> list, String []array)
	{
		try
		{			
			if(array == null || array.length < 1)
				return null;
			
			if(list == null)
				list = new LinkedList<String>();
			
			for(String token : array)
			{
				if(token == null || token.trim().equals(""))
					continue;
				
				if(list.contains(token.toLowerCase().trim()))
					continue;
				
				list.add(token.toLowerCase().trim());
			}
			
			/*if(Interface.PROFILE != null && Interface.PROFILE.toLowerCase().trim().startsWith("winxp"))
			{
				list_favorites.add("connections");
				list_favorites.add("connscan");
				list_favorites.add("sockets");
				list_favorites.add("sockscan");
			}
			else
			{
				list_favorites.add("netscan");
			}*/
			
			return list;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_list", e);
		}
		
		return null;
	}
	
	public static TreeMap<String, Plugin> get_selected_plugins()
	{
		try
		{
			if(tree_plugins== null || tree_plugins.isEmpty())
				return null;
			
			try	{	tree_selected_plugins.clear();}	catch(Exception e){	tree_selected_plugins = new TreeMap<String, Plugin>();}
			
			for(Plugin plugin : tree_plugins.values())
			{
				if(plugin == null || plugin.jcb == null)
					continue;
				
				if(plugin.jcb.isSelected())
					tree_selected_plugins.put(plugin.plugin_name, plugin);
					
			}
			
			return tree_selected_plugins;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_selected_plugins", e);
		}
		
		return null;
	}
	
	public static boolean selectFavorites()
	{
		try
		{
			if(tree_plugins == null || tree_plugins.isEmpty())
			{
				driver.jop_Error("Error! No plugins have been loaded...");
				return false;
			}
			
			//
			//update based on selected profile
			//
			if(Interface.PROFILE != null && Interface.PROFILE.toLowerCase().trim().startsWith("winxp"))
			{
				if(!list_favorites.contains("connections"))
					list_favorites.add("connections");
				
				
				if(!list_favorites.contains("connscan"))
					list_favorites.add("connscan");
				
				
				if(!list_favorites.contains("sockets"))
					list_favorites.add("sockets");
				
				
				if(!list_favorites.contains("sockscan"))
					list_favorites.add("sockscan");
			}
			else
			{
				if(!list_favorites.contains("netscan"))
					list_favorites.add("netscan");
			}
			
			//
			//select plugins
			//
			for(Plugin plugin : tree_plugins.values())
			{
				if(plugin.plugin_name != null && list_favorites.contains(plugin.plugin_name.toLowerCase().trim()))
					plugin.jcb.setSelected(true);						
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "selectFavorites", e);
		}
		
		return false;
	}
	
	
	
	public static boolean preview()
	{
		try
		{
			if(tree_plugins == null || tree_plugins.isEmpty())
			{
				driver.jop("Punt! Plugins are not loaded yet!");
				return false;
			}
			
			if(Interface.fle_volatility == null || !Interface.fle_volatility.exists() || !Interface.fle_volatility.isFile())
			{
				driver.jop("ERROR! You must select a valid volatility executable binary first!");
				return false;
			}
			
			if(Interface.fle_memory_image == null || !Interface.fle_memory_image.exists() || !Interface.fle_memory_image.isFile())
			{
				driver.jop("ERROR! You must select a valid memory image to analyze before continuing!");
				return false;
			}
			
			
			String profile_cmd = "--profile=" + Interface.PROFILE;
			if(Interface.PROFILE == null || Interface.PROFILE.trim().equals(""))
			{
				driver.jop("NOTE: A valid memory image profile is missing! This could contaminate analysis results!!!");
				profile_cmd = "";
			}
			
			
			
			int selected_plugins = 0;	
			String plugin_text = "";
			
			plugin_selected_dumpfiles = false;
			plugin_selected_pslist = false;
			plugin_selected_psscan = false;
			plugin_selected_pstree  = false;
			
			need_to_notify_of_additional_plugins = false;
			String required_plugins_to_add = "";
			
			//
			//for dumpfiles plugin, search if that plugin is selected, and if so, add the extra plugins to assist with naming 
			//these files
			//
			for(Plugin plugin : tree_plugins.values())
			{
				if(plugin == null)
					continue;
				
				if(plugin.plugin_name.equalsIgnoreCase("dumpfiles") && plugin.jcb.isSelected())
					plugin_selected_dumpfiles = true;
				
				else if(plugin.plugin_name.equalsIgnoreCase("pslist"))
				{
					if(plugin.jcb.isSelected())
						plugin_selected_pslist = true;
					else if(plugin_selected_dumpfiles)//only enable if dumpfiles is selected
					{
						required_plugins_to_add = required_plugins_to_add + "\n\t" + "- pslist";
						plugin.jcb.setSelected(true);
					}
				}
				
				else if(plugin.plugin_name.equalsIgnoreCase("psscan"))
				{
					if(plugin.jcb.isSelected())
						plugin_selected_psscan = true;
					else if(plugin_selected_dumpfiles)//only enable if dumpfiles is selected
					{
						required_plugins_to_add = required_plugins_to_add + "\n\t" + "- psscan";
						plugin.jcb.setSelected(true);
					}
				}
				
				else if(plugin.plugin_name.equalsIgnoreCase("pstree"))
				{
					if(plugin.jcb.isSelected())
						plugin_selected_pstree = true;
					else if(plugin_selected_dumpfiles)//only enable if dumpfiles is selected
					{
						required_plugins_to_add = required_plugins_to_add + "\n\t" + "- pstree";
						plugin.jcb.setSelected(true);
					}
				}
				
				
				//driver.directive(plugin.plugin_name + "  " + plugin.plugin_name.equalsIgnoreCase("dumpfiles"));
			}
			
			//analyze if it is required to add additional plugins
			if(plugin_selected_dumpfiles)
			{
								
				//
				//notify
				//
				if(required_plugins_to_add != null && required_plugins_to_add.trim().length() > 1)
				{
					driver.directive("\nNOTE: Since you selected the dumpfiles plugin, it is best if this plugin works with pslist, psscan, and pstree.\n      I have added the necessary plugins to assist with this analysis.");
				}
					
			}
			
			
			//determine if a plugin has been added yet
			for(Plugin plugin : tree_plugins.values())
			{
				if(plugin == null)
					continue;
				
				if(!plugin.jcb.isSelected())
					continue;
				
				++selected_plugins;
				
				//
				//determine if we're adding a new plugin
				//
				if(plugin.jtaConsole == null)
				{
					plugin.jtaConsole = new JTextArea_Solomon("", true, plugin.plugin_name, true);
					
					if(plugin.myJTabbedPane != null)					
						plugin.myJTabbedPane.addTab(plugin.plugin_name, plugin.jtaConsole);
					else
						Interface.jtabbedPane_ANALYSIS.addTab(plugin.plugin_name, plugin.jtaConsole);
					
					//set the command
					plugin.jtaConsole.jtf.setText(Interface.fle_volatility.getName() + " -f " + Interface.fle_memory_image.getName() + " " + plugin.plugin_name + " " + profile_cmd);
					
					//update the gui
					plugin.update_gui();
					
					//
					//set text for special plugins
					//
					
					
					//////////////////////////////
					//procdump
					//////////////////////////////
					if(plugin.plugin_name.equalsIgnoreCase("procdump"))
					{
						try	{	Interface.fle_procdump.mkdirs();	}	catch(Exception e){}
						//plugin.jtaConsole.jtf.setText(Interface.fle_volatility.getName() + " -f " + Interface.fle_memory_image.getName() + " " + plugin.plugin_name + " -p <PID> " + profile_cmd + " --dump -dir \"" + Interface.fle_procdump.getCanonicalPath() + "\"");
						
						plugin.jtaConsole.jtf.setText(Interface.fle_volatility.getName() + " -f " + Interface.fle_memory_image.getName() + " " + plugin.plugin_name + " " + profile_cmd);
						//plugin.jtaConsole.jtf.setText(Interface.fle_volatility.getName() + " -f " + Interface.fle_memory_image.getName() + " " + plugin.plugin_name + " " + profile_cmd + " --dump-dir \"" + Interface.fle_procdump + File.separator + "\"");
						//plugin.jtaConsole.jtf.setText(Interface.fle_volatility.getName() + " -f " + Interface.fle_memory_image.getName() + " " + plugin.plugin_name + " " + profile_cmd + " --dump-dir ./");

						
					}

					//////////////////////////////
					//ADD DUMP DIR
					//////////////////////////////
					else if (	plugin.plugin_name.equalsIgnoreCase("dlldump") 		||
								plugin.plugin_name.equalsIgnoreCase("dumpcerts") 	||
								plugin.plugin_name.equalsIgnoreCase("dumpfiles") 	||
								plugin.plugin_name.equalsIgnoreCase("dumpregistry") ||
								plugin.plugin_name.equalsIgnoreCase("memdump") 		||
								plugin.plugin_name.equalsIgnoreCase("moddump") 		||
								plugin.plugin_name.equalsIgnoreCase("evtlogs") 		||
								plugin.plugin_name.equalsIgnoreCase("vaddump") 		
							)
					{
						plugin.jtaConsole.jtf.setText(Interface.fle_volatility.getName() + " -f " + Interface.fle_memory_image.getName() + " " + plugin.plugin_name + " " + profile_cmd);						
					}
			
					
					
					
					
					
					
					
				}
					
				//
				//set the module command
				//
				plugin_text = plugin.jtaConsole.jtf.getText();
				if(plugin_text == null) plugin_text = "null";
				plugin_text = plugin_text.toLowerCase().trim();
				
				
				//
				//RESET THE COMMAND IF REQUIRED
				//
				if(plugin_text.equalsIgnoreCase("null") || plugin_text.equalsIgnoreCase("reset")|| plugin_text.equalsIgnoreCase("help")|| plugin_text.equalsIgnoreCase("-1")|| plugin_text.equalsIgnoreCase("-"))
				{
					//////////////////////////////
					//procdump
					//////////////////////////////
//					if(plugin.plugin_name.equalsIgnoreCase("procdump"))
//					{
//						try	{	Interface.fle_procdump.mkdirs();	}	catch(Exception e){}
//						plugin.jtaConsole.jtf.setText(Interface.fle_volatility.getName() + " -f " + Interface.fle_memory_image.getName() + " " + plugin.plugin_name + " -p <PID> " + profile_cmd + " --dump -dir \"" + Interface.fle_procdump.getCanonicalPath() + "\"");
//
//						
//					}
					
					if (	plugin.plugin_name.equalsIgnoreCase("procdump") 	||
							plugin.plugin_name.equalsIgnoreCase("dlldump") 		||
							plugin.plugin_name.equalsIgnoreCase("dumpcerts") 	||
							plugin.plugin_name.equalsIgnoreCase("dumpfiles") 	||
							plugin.plugin_name.equalsIgnoreCase("dumpregistry") ||
							plugin.plugin_name.equalsIgnoreCase("memdump") 		||
							plugin.plugin_name.equalsIgnoreCase("moddump")		||
							plugin.plugin_name.equalsIgnoreCase("evtlogs") 		||
							plugin.plugin_name.equalsIgnoreCase("vaddump")
						)
					{
						plugin.jtaConsole.jtf.setText(Interface.fle_volatility.getName() + " -f " + Interface.fle_memory_image.getName() + " " + plugin.plugin_name + " " + profile_cmd);						
					}

					//////////////////////////////
					//SET ALL OTHER TEXT!
					//////////////////////////////

					//set text
					else
						plugin.jtaConsole.jtf.setText(Interface.fle_volatility.getName() + " -f " + Interface.fle_memory_image.getName() + " " + plugin.plugin_name + " " + profile_cmd);

				}
				
				//
		        //request focus
		        //
		        //try	{	Interface.jtabbedPane_CONSOLE.setSelectedComponent(Interface.jtabbedPane_ANALYSIS);} catch(Exception e){}
		        
		        
				
				


				


			
			
				
					
			}//end for
			
			
			
			if(selected_plugins < 1)
			{
				driver.jop("You must select at least 1 plugin in order to continue...");
				return false;
			}
			
			//
			//analyze specific plugins
			//
			/*if(plugin_selected_dumpfiles)
			{
				//to work best, it's good to select psscan, pstree, and pslist to create the list of PIDs and their process names
				//make sure each plugin is selected
								
				Plugin dependency = null;
				
				//
				//pstree
				//
				String dependency_name = "pstree";				
				if(tree_plugins.containsKey(dependency_name))
				{
					dependency = tree_plugins.get(dependency_name);
					
					if(dependency != null)
					{
						if(!dependency.jcb.isSelected())
						{
							need_to_notify_of_additional_plugins = true;
							dependency.jcb.setSelected(true);	
							add_plugin(dependency_name);
						}
					}
				}
				
				//
				//psscan
				//
				dependency_name = "psscan";				
				if(tree_plugins.containsKey(dependency_name))
				{
					dependency = tree_plugins.get(dependency_name);
					
					if(dependency != null)
					{
						if(!dependency.jcb.isSelected())
						{
							need_to_notify_of_additional_plugins = true;
							dependency.jcb.setSelected(true);		
							add_plugin(dependency_name);
						}
					}
				}
				
				//
				//pslist
				//
				dependency_name = "pslist";				
				if(tree_plugins.containsKey(dependency_name))
				{
					dependency = tree_plugins.get(dependency_name);
					
					if(dependency != null)
					{
						if(!dependency.jcb.isSelected())
						{
							need_to_notify_of_additional_plugins = true;
							dependency.jcb.setSelected(true);	
							add_plugin(dependency_name);
						}
					}
				}
				
				
			}*///end if for plugin_selected_dumpfiles
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "PREVIEW", e);
		}
		
		return false;
	}
	
	/*public boolean add_plugin(String plugin_NAME)
	{
		try
		{
			if(plugin.jtaConsole == null)
			{
				plugin.jtaConsole = new JTextArea_Solomon("", true, plugin.plugin_name, true);
				
				if(plugin.myJTabbedPane != null)					
					plugin.myJTabbedPane.addTab(plugin.plugin_name, plugin.jtaConsole);
				else
					Interface.jtabbedPane_ANALYSIS.addTab(plugin.plugin_name, plugin.jtaConsole);
				
				//set the command
				plugin.jtaConsole.jtf.setText(Interface.fle_volatility.getName() + " -f " + Interface.fle_memory_image.getName() + " " + plugin.plugin_name + " " + profile_cmd);
				
				//update the gui
				plugin.update_gui();
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "add_plugin", e);
		}
		
		return false;
	
	}*/
	
	public static boolean analyze_image()
	{
		try
		{
			//run preview
			preview();
			
			
			if(Interface.fle_memory_image == null || !Interface.fle_memory_image.exists() || !Interface.fle_memory_image.isFile())
			{
				driver.jop_Error("You must specify a valid memory image file before proceeding", false);
				return false;
			}
			
			TreeMap<String, Plugin> tree_selected_plugins = Plugin.get_selected_plugins();
			
			if(tree_selected_plugins == null || tree_selected_plugins.isEmpty())
			{
				driver.jop_Error("No plugins are selected. \nPlease select applicable plugin(s) before proceeding", false);
				return false;
			}
			
			String cmd = "";
			int plugins_executed = 0;
			
			for(Plugin plugin : tree_selected_plugins.values())
			{
				cmd = plugin.jtaConsole.jtf.getText();
				
				if(cmd == null)
					cmd = "null";
				cmd = cmd.trim();
				
				//skip blank entries
				if(cmd == null || cmd.equals("") || cmd.equalsIgnoreCase("help") || cmd.equalsIgnoreCase("null") || cmd.equalsIgnoreCase("-") || cmd.equalsIgnoreCase("reset") || cmd.equalsIgnoreCase("-1"))				
					continue;
				
				++plugins_executed;
					
				Process_Plugin process = new Process_Plugin(plugin, plugin.plugin_name, plugin.plugin_description, plugin.jtaConsole.jtf.getText(), true);
				
				//clear the text after execution
				if(clear_text_after_execution)
				{
					try
					{
						if(!plugin.jtaConsole.history.contains(plugin.jtaConsole.jtf.getText().trim()))
							plugin.jtaConsole.history.add(plugin.jtaConsole.jtf.getText().trim());
					}catch(Exception e){}					
							
							
					plugin.jtaConsole.jtf.setText("");
				}
			}
			
			if(plugins_executed < 1)
				driver.jop("NOTE: No new commands were executed!");
			else
				driver.directive("\nNumber of plugin requests I just tried to execute: [" + plugins_executed + "].");
				
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_image", e);
		}
		
		return false;
	}
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == jbtnOpenOutputFile)
			{
				if(this.fleOutput == null || !fleOutput.exists() || !fleOutput.isFile())
				{
					driver.jop_Error("Nope!!!!  Output file does not appear to exist!", false);
				}
				else
					driver.open_file(fleOutput);
			}
			
			if(ae.getSource() == jbtnOpenOutputDirectory)
			{
				if(this.fleOutput == null || !fleOutput.exists() || !fleOutput.isFile())
				{
					driver.jop_Error("Nope!!!!  Output directory is not ready yet... (since output file has not been created)!", false);
				}
				else
					driver.open_file(fleOutput.getParentFile());
			}
			
			else if(this.jtaConsole != null && (ae.getSource() == jtaConsole.jbtnSend || ae.getSource() == jtaConsole.jtf))
			{
				this.execute_command();
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
			
		try	{	this.validate();} catch(Exception e){}
		try	{	if(this.jtaConsole != null) jtaConsole.validate();} catch(Exception e){}
		
	}
	
	
	public boolean execute_command()
	{
		try
		{
			String cmd = jtaConsole.jtf.getText();
			
			if(cmd == null)
				cmd = "null";
			cmd = cmd.trim();
			
			//skip blank entries
			if(cmd == null || cmd.equals("") || cmd.equalsIgnoreCase("help") || cmd.equalsIgnoreCase("null") || cmd.equalsIgnoreCase("-") || cmd.equalsIgnoreCase("reset") || cmd.equalsIgnoreCase("-1"))				
			{
				driver.jop("No command to execute for plugin: [" + plugin_name + "]");
				return false;
			}			
				
			Process_Plugin process = new Process_Plugin(this, this.plugin_name, this.plugin_description, this.jtaConsole.jtf.getText(), true);
			
			//clear the text after execution
			if(clear_text_after_execution)
			{
				try
				{
					if(!this.jtaConsole.history.contains(this.jtaConsole.jtf.getText().trim()))
						this.jtaConsole.history.add(this.jtaConsole.jtf.getText().trim());
				}catch(Exception e){}					
						
						
				this.jtaConsole.jtf.setText("");
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_command", e);
		}
		
		return false;
	}
	
	
	public boolean update_gui()
	{
		try
		{
			if(this.jtaConsole == null)
				return false;
			
			jtaConsole.jbtnClear.setText("Clear Output");
			jtaConsole.jbtnSend.setText("Execute");
			
			try	{	jtaConsole.jtf.removeActionListener(jtaConsole); } catch(Exception e){}
			try	{	jtaConsole.jbtnSend.removeActionListener(jtaConsole); } catch(Exception e){}
			
			jtaConsole.jtf.addActionListener(this);
			jtaConsole.jbtnSend.addActionListener(this);
			jbtnOpenOutputFile.addActionListener(this);
			jbtnOpenOutputDirectory.addActionListener(this);
			
			jtaConsole.jpnlcheckBox.add(this.jbtnOpenOutputFile);
			jtaConsole.jpnlcheckBox.add(this.jbtnOpenOutputDirectory);
			jbtnOpenOutputFile.setEnabled(false);
			jbtnOpenOutputDirectory.setEnabled(false);
			
			
			try	{	this.validate();} catch(Exception e){}
			try	{	if(this.jtaConsole != null) jtaConsole.validate();} catch(Exception e){}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_gui", e);
		}
		
		return false;
					
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
