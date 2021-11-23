/**
 * @author Solomon Sonya
 */

package Interface;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.plaf.basic.BasicSplitPaneDivider;

import javafx.*;
import javafx.embed.swing.JFXPanel;

public class JSplitPane_Solomon extends JPanel
{
	public JSplitPane jsplitpane = null;
	
	BasicSplitPaneDivider divider = null;
	
	/**
	 * JSplitPane.HORIZONTAL_SPLIT
	 * @param SPLIT_TYPE
	 * @param jpnl1
	 * @param jpnl2
	 */
	public JSplitPane_Solomon(int SPLIT_TYPE, JPanel jpnl1, JPanel jpnl2, int divider_location)
	{
		try
		{
			jsplitpane = new JSplitPane(SPLIT_TYPE, jpnl1, jpnl2);
			jsplitpane.setOneTouchExpandable(true);
			jsplitpane.setDividerLocation(divider_location);
			this.jsplitpane.setDividerSize(10);
			jpnl1.setMinimumSize(new Dimension(1,1));
			jpnl2.setMinimumSize(new Dimension(1,1));
					
			this.setLayout(new BorderLayout());
			
			this.add(BorderLayout.CENTER, jsplitpane);
		}
		catch(Exception e)
		{
			System.out.println("Exception caught in JSplitPane_Solomon class - Constructor -1 mtd");
		}
	}
	
	public JSplitPane_Solomon(int SPLIT_TYPE, JScrollPane jpnl1, JPanel jpnl2, int divider_location)
	{
		try
		{
			jsplitpane = new JSplitPane(SPLIT_TYPE, jpnl1, jpnl2);
			jsplitpane.setOneTouchExpandable(true);
			jsplitpane.setDividerLocation(divider_location);
			this.jsplitpane.setDividerSize(10);
			jpnl1.setMinimumSize(new Dimension(1,1));
			jpnl2.setMinimumSize(new Dimension(1,1));
			
					
			this.setLayout(new BorderLayout());
			
			this.add(BorderLayout.CENTER, jsplitpane);
		}
		catch(Exception e)
		{
			System.out.println("Exception caught in JSplitPane_Solomon class - Constructor -1 mtd");
		}
	}
	
	public JSplitPane_Solomon(int SPLIT_TYPE, JScrollPane jpnl1, JScrollPane jpnl2, int divider_location)
	{
		try
		{
			jsplitpane = new JSplitPane(SPLIT_TYPE, jpnl1, jpnl2);
			jsplitpane.setOneTouchExpandable(true);
			jsplitpane.setDividerLocation(divider_location);
			this.jsplitpane.setDividerSize(10);
			jpnl1.setMinimumSize(new Dimension(1,1));
			jpnl2.setMinimumSize(new Dimension(1,1));
			
					
			this.setLayout(new BorderLayout());
			
			this.add(BorderLayout.CENTER, jsplitpane);
		}
		catch(Exception e)
		{
			System.out.println("Exception caught in JSplitPane_Solomon class - Constructor -1 mtd");
		}
	}
	
	public JSplitPane_Solomon(int SPLIT_TYPE, JSplitPane_Solomon jpnl1,  JScrollPane jpnl2, int divider_location)
	{
		try
		{
			jsplitpane = new JSplitPane(SPLIT_TYPE, jpnl1, jpnl2);
			jsplitpane.setOneTouchExpandable(true);
			jsplitpane.setDividerLocation(divider_location);
			this.jsplitpane.setDividerSize(10);
			jpnl1.setMinimumSize(new Dimension(1,1));
			jpnl2.setMinimumSize(new Dimension(1,1));
			
					
			this.setLayout(new BorderLayout());
			
			this.add(BorderLayout.CENTER, jsplitpane);
		}
		catch(Exception e)
		{
			System.out.println("Exception caught in JSplitPane_Solomon class - Constructor -1 mtd");
		}
	}
	
	/**
	 * JSplitPane.HORIZONTAL_SPLIT
	 * @param SPLIT_TYPE
	 * @param jpnl1
	 * @param jpnl2
	 */
	public JSplitPane_Solomon(int SPLIT_TYPE, JFXPanel jpnl1, JPanel jpnl2, int divider_location)
	{
		try
		{
			jsplitpane = new JSplitPane(SPLIT_TYPE, jpnl2, jpnl1);
			jsplitpane.setOneTouchExpandable(true);
			jsplitpane.setDividerLocation(divider_location);
			this.jsplitpane.setDividerSize(10);
			jpnl1.setMinimumSize(new Dimension(1,1));
			jpnl2.setMinimumSize(new Dimension(1,1));
			
					
			this.setLayout(new BorderLayout());
			
			this.add(BorderLayout.CENTER, jsplitpane);
		}
		catch(Exception e)
		{
			System.out.println("Exception caught in JSplitPane_Solomon class - Constructor -1 mtd");
		}
	}
	
	public JSplitPane_Solomon(int SPLIT_TYPE, JTabbedPane jpnl1, JTabbedPane jpnl2, int divider_location)
	{
		try
		{
			jsplitpane = new JSplitPane(SPLIT_TYPE, jpnl1, jpnl2);
			jsplitpane.setOneTouchExpandable(true);
			jsplitpane.setDividerLocation(divider_location);
			this.jsplitpane.setDividerSize(11);
			jpnl1.setMinimumSize(new Dimension(1,1));
			jpnl2.setMinimumSize(new Dimension(1,1));
			
			this.setLayout(new BorderLayout());
			
			this.add(BorderLayout.CENTER, jsplitpane);
		}
		catch(Exception e)
		{
			System.out.println("Exception caught in JSplitPane_Solomon class - Constructor -1 mtd");
		}
	}
	
	public JSplitPane_Solomon(int SPLIT_TYPE, JPanel jpnl1, JTabbedPane jpnl2, int divider_location)
	{
		try
		{
			jsplitpane = new JSplitPane(SPLIT_TYPE, jpnl1, jpnl2);
			jsplitpane.setOneTouchExpandable(true);
			jsplitpane.setDividerLocation(divider_location);
			this.jsplitpane.setDividerSize(11);
			jpnl1.setMinimumSize(new Dimension(1,1));
			jpnl2.setMinimumSize(new Dimension(1,1));
			
			this.setLayout(new BorderLayout());
			
			this.add(BorderLayout.CENTER, jsplitpane);
		}
		catch(Exception e)
		{
			System.out.println("Exception caught in JSplitPane_Solomon class - Constructor -1 mtd");
		}
	}
	
	public JSplitPane_Solomon(int SPLIT_TYPE, JTabbedPane jpnl1, JSplitPane_Solomon jpnl2, int divider_location)
	{
		try
		{
			jsplitpane = new JSplitPane(SPLIT_TYPE, jpnl1, jpnl2);
			jsplitpane.setOneTouchExpandable(true);
			jsplitpane.setDividerLocation(divider_location);
			this.jsplitpane.setDividerSize(11);
			jpnl1.setMinimumSize(new Dimension(1,1));
			jpnl2.setMinimumSize(new Dimension(1,1));
			
			this.setLayout(new BorderLayout());
			
			this.add(BorderLayout.CENTER, jsplitpane);
		}
		catch(Exception e)
		{
			System.out.println("Exception caught in JSplitPane_Solomon class - Constructor -1 mtd");
		}
	}
}
