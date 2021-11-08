package SearchImage;

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

public class SearchImage extends JPanel implements ActionListener
{
	public static final String myClassName = "SearchImage";
	public static volatile Driver driver = new Driver();

	public volatile File fle = null;
	public volatile FileAttributeData attributes= null;
	 
	public volatile JPanel jpnlNorth = new JPanel(new BorderLayout());
	
	public JLabel jlblFilePath = new JLabel("  File Path: unspecified...");
	public JLabel jlblFileAttributes = new JLabel("  ");
	
	public JPanel jpnlKeywords = new JPanel(new BorderLayout());
		JTextField jtfKeywords = new JTextField(12);
		JCheckBox jcbIncludeContext = new JCheckBox("Include [" + Process_SearchImage.MAX_BYTES_TO_READ + "] byte context", false);
		public JPanel jpnlButtons = new JPanel();
			JButton jbtnAnalyze = new JButton("Analyze");
			JButton jbtnStop = new JButton("Stop");
			JButton jbtnOpenFile = new JButton("Open File");
			JButton jbtnOpenDirectory = new JButton("Open Directory");
			public JButton jbtnSearchImage = new JButton("Add Search Tab");
			
	public JTextArea_Solomon jta  = null;
	
	public volatile boolean STOP = false;
	
	public volatile Process_SearchImage search = null;
	
	public SearchImage(File file, String path, String name)
	{
		try
		{
			fle = file;
			
			if(file == null || !file.exists() || !file.isFile())
			{
				driver.directive("PUNT! I am not able to commence actions on file [" + name + "] - file appears to be invalid at expected path --> " + path);
			}
			else			
			{
				initialize_component();
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - null", e);
		}
	}
	
	public boolean initialize_component()
	{
		try
		{
			attributes = new FileAttributeData(fle, true, true);
			this.jlblFilePath.setText("   Image Path: " + fle.getCanonicalPath());
			this.jlblFilePath.setToolTipText("Image Path: " + fle.getCanonicalPath());

			jta  = new JTextArea_Solomon("", true, "Search Image - " + fle.getName(), false);
			jta.jta.setWrapStyleWord(false);
			jta.jta.setLineWrap(false);

			try{jta.jpnlSouth.removeAll();}catch(Exception e){}
			jta.jpnlSouth.setLayout(new GridLayout(1,7,5,5));
			jta.jpnlSouth.add(this.jbtnAnalyze);
			jta.jpnlSouth.add(this.jbtnStop);
			jta.jpnlSouth.add(this.jta.jbtnExportData);
			jta.jpnlSouth.add(this.jbtnOpenFile);
			jta.jpnlSouth.add(jbtnOpenDirectory);			
			jta.jpnlSouth.add(jbtnSearchImage);
			
			JPanel jpnlScroll = new JPanel(new BorderLayout());
			jpnlScroll.add(BorderLayout.WEST, jta.jcbAutoScroll);
			jpnlScroll.add(BorderLayout.EAST, jta.jcbRejectUpdate);
			jta.jpnlSouth.add(jpnlScroll);
			
			
        	try	{	jta.jpnlSouth.setBorder(new TitledBorder("Options"));	}	catch(Exception e){}					
        	jta.add(BorderLayout.SOUTH, jta.jpnlSouth);
        	jta.validate();
        	jta.repaint();
        	
        	jta.jpnlSouth.repaint();
        	
        	this.setLayout(new BorderLayout());
        	
        	jpnlNorth.add(BorderLayout.NORTH, jlblFilePath);
        	jpnlNorth.add(BorderLayout.CENTER, jlblFileAttributes);
        	
        	jpnlKeywords.add(BorderLayout.CENTER, jtfKeywords);
        	jpnlKeywords.add(BorderLayout.EAST, jcbIncludeContext);
        	try	{	jpnlKeywords.setBorder(new TitledBorder("Keyword(s)"));	}	catch(Exception e){}
        	
        	jcbIncludeContext.setToolTipText("Enabling this option includes more context around the keyword hit.  Keeping disabled restricts the hit to the current word discovered.");
        	
        	/*jpnlButtons.add(jbtnAnalyze);
        	jpnlButtons.add(jbtnStop);
        		jpnlKeywords.add(BorderLayout.EAST, jpnlButtons);*/
        	
        	jpnlNorth.add(BorderLayout.SOUTH, jpnlKeywords);
        	
        	this.add(BorderLayout.NORTH, jpnlNorth);
        	
        	try	{	jta.setBorder(new TitledBorder("Search Results"));	}	catch(Exception e){}
        	this.add(BorderLayout.CENTER, jta);
			
        	this.jtfKeywords.addActionListener(this);
        	this.jbtnAnalyze.addActionListener(this);
        	this.jbtnOpenDirectory.addActionListener(this);
        	this.jbtnOpenFile.addActionListener(this);
        	this.jbtnStop.addActionListener(this);
        	jbtnSearchImage.addActionListener(this);
        	this.jcbIncludeContext.addActionListener(this);
        	
        	this.jtfKeywords.setToolTipText("Specify keywords to search here. Use the comma to delimit multiple keywords. Hit ENTER on keyboard or press Analyze button to commence analysis.");
        	this.jbtnAnalyze.setToolTipText("Specify keywords in the textfield above. Use the comma to delimit multiple keywords");
        	this.jbtnStop.setToolTipText("Click if you wish to halt further searching through the image.");
        	this.jbtnOpenDirectory.setToolTipText("Click to open the output directory storing results of your keyword search.");
        	this.jbtnOpenDirectory.setToolTipText("Click to open the output file storing results of your keyword search.");
        	jbtnSearchImage.setToolTipText("<html>Enter specific keywords to search for hits through a specified image. <br>A new Tab will appear to allow you to select an image and enter keywords to search for hits.</html>");
        	
        	this.validate();
        	this.repaint();
        	
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_component", e);
		}
		
		return false;
	}
	
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == this.jbtnAnalyze)
			{
				analyze();
			}
			
			else if(ae.getSource() == this.jtfKeywords)
			{
				analyze();
			}
			
			else if(ae.getSource() == jbtnSearchImage)
			{
				Interface.add_search_image();
			}
			
			else if(ae.getSource() == jcbIncludeContext)
			{
				if(this.search != null)
				{
					try	{	search.include_full_context_around_keyword_hit = this.jcbIncludeContext.isSelected();	}catch(Exception e){}
				}
			}
			
			else if(ae.getSource() == this.jbtnOpenDirectory)
			{
				if(this.search != null && search.fle_out != null && search.fle_out.exists())
				{
					driver.open_file(search.fle_out.getParentFile());
				}
				else
				{
					driver.jop_Error("Punt! No valid search results output file has been created yet...", false);
				}
			}
			
			else if(ae.getSource() == this.jbtnOpenFile)
			{
				if(this.search != null && search.fle_out != null && search.fle_out.exists())
				{
					driver.open_file(search.fle_out);
				}
				else
				{
					driver.jop_Error("Punt! No valid search results output file has been created yet...", false);
				}
			}
			
			else if(ae.getSource() == this.jbtnStop)
			{
				STOP = true;
				if(search != null)
					search.STOP = true;
			}
			
						
			
			this.validate();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	
	
	public boolean analyze()
	{
		try
		{
			STOP = false;
			
			String keywords = this.jtfKeywords.getText().trim();
			
			keywords = keywords.trim();
			
			if(keywords.equals(""))
			{
				driver.jop_Error("Please specify at least one keyword. \nMultiple keywords can be separated with commas", false);
				return false;
			}
			
			String [] array = keywords.split(",");
			
			if(array == null || array.length < 1)
				array = new String[]{keywords};
			
			//trim the keywords
			for(int i = 0; i < array.length; i++)
				array[i] = array[i].trim();
			
			search = new Process_SearchImage(this, fle, array, keywords, attributes, this.jcbIncludeContext.isSelected());						
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
