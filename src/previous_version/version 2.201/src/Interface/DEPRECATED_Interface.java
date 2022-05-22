package Interface;

import java.io.*;
import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.TitledBorder;
import Driver.*;
import GEO_Location.GEO_Location;


public class DEPRECATED_Interface extends Thread implements Runnable
{
	
	public static final String myClassName = "Interface";
	public static volatile Driver driver = new Driver();
	
	public volatile JPanel jpnlMain = null;
	public volatile JPanel jpnlNorth = null;
	public volatile JPanel jpnlCenter = null;
	public volatile JPanel jpnlSouth = null;
	
	public static volatile JFrame jfrm = null;
	
	
	public DEPRECATED_Interface()
	{
		try
		{
			this.start();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - null", e);
		}
		
	}
	
	public void run()
	{
		try
		{
			this.initialize_component();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean initialize_component()
	{
		try
		{
			driver.setLookAndFeel();
			try 		 {				 UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");				 SwingUtilities.updateComponentTreeUI(jfrm);				 /*updateComponentTreeUI(this);	*/	    }	catch (Exception e) 	    {	    }
			
			jfrm = new JFrame();			
			jfrm.setTitle(Driver.FULL_NAME);
			jfrm.setSize(new Dimension(1100,800));
			jfrm.setVisible(true);
			jfrm.setLayout(new BorderLayout());
			
			try			{				jfrm.setLocationRelativeTo(null);			}
			catch(Exception e)
			{
				Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
				jfrm.setLocation(dim.width/2-jfrm.getSize().width/2, dim.height/2-jfrm.getSize().height/2);
			}
			
			jfrm.addWindowListener(new java.awt.event.WindowAdapter()
			{
				public void windowClosing(java.awt.event.WindowEvent e)
				{
					close();
				}
			});
			
			jfrm.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_component", e);
		}
		
		return false;
	}
	
	
	public boolean close()
	{
		try
		{
			if(driver.query_user("Close " + Driver.NAME + "?", "Exit?") == JOptionPane.YES_OPTION)
			{
				
				if(driver.isWindows)
				{
					//try	{	Process p = Runtime.getRuntime().exec("cmd.exe /C " + "\"" + "taskkill /f /im tshark*" + "\"");	}	catch(Exception e){}
					//try	{	Process p = Runtime.getRuntime().exec("cmd.exe /C " + "\"" + "taskkill /f /im dumpcap*" + "\"");	}	catch(Exception e){}
				}
				else if(driver.isLinux)
				{
					//String [] cmd = new String [] {"/bin/bash", "-c", SENSOR_COMMAND};
					//Process p = Runtime.getRuntime().exec(cmd);					
				}
				
				driver.directive("Program Terminated.");
				System.exit(0);
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "close", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
