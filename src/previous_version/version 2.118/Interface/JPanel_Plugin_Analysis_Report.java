/**
 * Present the GUI for the user to select a plugin to execute
 */

package Interface;

import java.awt.BorderLayout;
import java.util.LinkedList;

import javax.swing.*;
import Driver.*;
import Plugin.*;

public class JPanel_Plugin_Analysis_Report extends JPanel
{
	public static Driver driver = new Driver();
	public static final String myClassName = "JPanel_Plugin_Analysis_Report";

	public static final int max_report_text_length = 30;
	
	Plugin plugin = null;
	
	public JButton jbtnReport_Add = new JButton("Add");
	public JButton jbtnReport_Remove = new JButton("Remove");
	public JLabel jlblReport_Title = new JLabel("", JLabel.LEFT);
	public JButton jbtnReport_MoveUp = new JButton("Up");
	public JButton jbtnReport_MoveDown = new JButton("Down");
	
	public String plugin_description = "";
	public String plugin_name = "";
	
public volatile boolean is_selected_for_analysis_report = false;
	
	public JPanel jpnlReport = new JPanel(new BorderLayout());
	
	public JPanel jpnlReport_WEST = new JPanel();
	public JPanel jpnlReport_CENTER = new JPanel();
	public JPanel jpnlReport_move_buttons = new JPanel();
	
	public JPanel jpnlReport_add_remove_buttons = new JPanel();
	
	public volatile Process_Plugin process_plugin = null;
	
	public JPanel_Plugin_Analysis_Report(Plugin parent_plugin)
	{
		try
		{
			plugin = parent_plugin;
			
			populate_report_instance();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	public boolean populate_report_instance()
	{
		try
		{
			plugin_description = plugin.plugin_description;
			plugin_name = plugin.plugin_name;
			
			String text = "";
			if(plugin_description != null && plugin_description.length() > max_report_text_length)
			{
				LinkedList<String> list = driver.tokenize(plugin_description, max_report_text_length);
				
				if(list == null || list.size() < 1)
					text = "<html><b><u>" + plugin_name + "</b></u>\t" + " - " + plugin_description + "</html>";
				else
				{
					String plugin_name_tokenized = list.removeFirst();
					
					for(String str : list)
					{
						plugin_name_tokenized = plugin_name_tokenized + "<br>" + str;
					}
					
					text = "<html><b><u>" + plugin_name + "</b></u>\t" + " - " + plugin_name_tokenized + "</html>";
				}
			}
			else
				text = "<html><b><u>" + plugin_name + "</b></u>\t" + " - " + plugin_description + "</html>";
			
			
			//this.jlblReport_Title.setText("<html><b><u>" + plugin_name + "</b></u>\t" + " - " + plugin_description + "</html>");		
			this.jlblReport_Title.setText(text);
			this.jlblReport_Title.setToolTipText("<html><b><u>" + plugin_name + "</b></u>\t" + " - " + plugin_description + "</html>");

			
			jpnlReport_add_remove_buttons.add(jbtnReport_Add);
			jpnlReport_add_remove_buttons.add(jbtnReport_Remove);
			jpnlReport_add_remove_buttons.add(jlblReport_Title);
				jpnlReport_WEST.add(jpnlReport_add_remove_buttons);
			
			
			jpnlReport_move_buttons.add(jbtnReport_MoveUp);
			jpnlReport_move_buttons.add(jbtnReport_MoveDown);
			
			jbtnReport_MoveUp.setToolTipText("Move this Plugin higher in the list");
			jbtnReport_MoveDown.setToolTipText("Move this Plugin lower in the list");
			
			jpnlReport.add(BorderLayout.WEST, jpnlReport_WEST);
			//jpnlReport.add(BorderLayout.CENTER, jpnlReport_CENTER);
			jpnlReport.add(BorderLayout.EAST, jpnlReport_move_buttons);
			
			//actionlis
			
			this.add(this.jpnlReport);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_report_instance", e);
		}
		
		return false;
		
	}
	
	
	
	
	
	
	
	

}
