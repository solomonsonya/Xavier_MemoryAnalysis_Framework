/**
 * @author Solomon Sonya
 */


package Interface;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import Driver.*;
//import Sound.ThreadSound;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.LinkedList;

public class JTextArea_Solomon extends JPanel implements ActionListener, KeyListener
{	
	public static final String VERSION_JTextArea = "1.004";
	public static final String myClassName = "JTextArea_Solomon";
	public static volatile Driver driver = new Driver();
	
	public static final int MAX_CHAR_LEN = -1;

	public JScrollPane jscrlpne = null;
	public JTextArea jta = new JTextArea(10,10);
	
	JPanel jpnlCENTER = new JPanel(new BorderLayout());
	
	public volatile LinkedList<String> history = new LinkedList<String>();
	public static final int MAX_HISTORY_COUNT = 30;
	public volatile int history_index = 0;
		
	
	int lineCount = 0;
	public volatile boolean restrict_data_entries = true;
	public final int maxLineCount = Integer.MAX_VALUE;
	
	public JPanel jpnlSouth = new JPanel(new BorderLayout());
	public JTextField jtf = new JTextField(12);
	public JButton jbtnSend = new JButton("Send");
	public JPanel jpnlcheckBox = new JPanel(new GridLayout(1,6));
	public JCheckBox jcbRejectUpdate = new JCheckBox("Reject Update");
	public JButton jbtnClear = new JButton("Clear");
	public JCheckBox jcbAutoScroll = new JCheckBox("AutoScroll", true);
	
	public JLabel jlblHeading = new JLabel("", JLabel.CENTER);
	
	public volatile String line = "";
	
	public volatile JButton jbtnExportData = new JButton("Export Data");
	
	
	public JTextArea_Solomon(String header, boolean console_interaction, String command_gransmission_title, boolean include_standard_buttons)
	{
		try
		{
			if(header != null && !header.trim().equals(""))
				this.jlblHeading.setText(header);
			
			
			this.setLayout(new BorderLayout());
			
			this.add(BorderLayout.NORTH, this.jlblHeading);
			
			this.jscrlpne = new JScrollPane(this.jta, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			jpnlCENTER.add(BorderLayout.CENTER, this.jscrlpne);
			this.add(BorderLayout.CENTER, this.jpnlCENTER);
			
			this.jta.setBackground(Color.white);
			
			
			if(include_standard_buttons)
				populate_console_buttons(true, true, true, true, true, false);
			
			
//			jpnlSouth.add(BorderLayout.EAST, jpnlcheckBox);
//			jpnlSouth.add(BorderLayout.CENTER, jtf);
//			try	{	this.jpnlSouth.setBorder(new TitledBorder(command_gransmission_title));	}	catch(Exception e){}
			
			if(console_interaction)
			{
				jpnlSouth.add(BorderLayout.EAST, jpnlcheckBox);
				jpnlSouth.add(BorderLayout.CENTER, jtf);
				try	{	this.jpnlSouth.setBorder(new TitledBorder(command_gransmission_title));	}	catch(Exception e){}
				
				this.add(BorderLayout.SOUTH, jpnlSouth);
			}
			
			
			jlblHeading.setForeground(Color.blue.darker());
			
			this.jbtnSend.addActionListener(this);
			this.jtf.addActionListener(this);
			this.jbtnClear.addActionListener(this);
			this.jtf.addKeyListener(this);
								
			jbtnExportData.addActionListener(this);
			jbtnExportData.setToolTipText("Click to save the output in the console out to disk.");
			
			this.validate();
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public boolean populate_console_buttons(boolean include_jbtnSend, boolean include_jbtnClear, boolean include_jcbAutoScroll, boolean include_jcbRejectUpdate, boolean include_export_data, boolean include_export_table)
	{
		try
		{
			if(include_jbtnSend)
				jpnlcheckBox.add(jbtnSend);
			if(include_jbtnClear)
				jpnlcheckBox.add(jbtnClear);
			if(include_jcbAutoScroll)
				jpnlcheckBox.add(jcbAutoScroll);
			/*if(include_jcbRejectUpdate)
				jpnlcheckBox.add(jcbRejectUpdate);*/
			if(include_export_data)
				jpnlcheckBox.add(this.jbtnExportData);
			
			jbtnExportData.setToolTipText("Click to save the output in the console out to disk.");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_console_buttons", e);
		}
		
		return false;
	}
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == this.jbtnClear)
			{
				clear();
				System.gc();
			}
			
			else if(ae.getSource() == this.jtf)
			{
				if(this.jtf.getText().equalsIgnoreCase("cls") || this.jtf.getText().equalsIgnoreCase("clr") || this.jtf.getText().equalsIgnoreCase("clear"))
				{
					this.jtf.setText("");
					this.jta.setText("");
				}
				else
				{
					send();
				}
				
				System.gc();
			}
			
			else if(ae.getSource() == this.jbtnSend)
			{
				send();
			}
			
			
			else if(ae.getSource() == jbtnExportData)
			{
				export_data();
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
		
		this.validate();
	}
	
	public File export_data()
	{
		try
		{						
			File fle = driver.querySelectFile(false, "Please Export Location...", JFileChooser.FILES_AND_DIRECTORIES, false, false);
			
			if(fle == null)
			{
				return null;
			}
			
			
			
			String path = fle.getCanonicalPath().trim();
			String file_name = "";
			
			if(fle.isDirectory())
			{
				if(!path.endsWith(File.separator))
					path = path + File.separator;
				
				file_name = path + "data_export_" + driver.get_time_stamp_hyphenated() + ".txt";
			}
			
			else//keep entire file name entered
			{
				file_name = fle.getCanonicalPath().trim();
			}						
			
			
			File fleOut = new File(file_name);
			
			//Create new file
			PrintWriter pwOut = null;
			
			try
			{
				pwOut = new PrintWriter(new FileWriter(fleOut, true));
			}
			catch(Exception e)
			{
				File f = new File("." + File.separator + Driver.NAME_LOWERCASE + File.separator + "export" + File.separator);
				
				try	{	f.mkdirs();	}catch(Exception ee){}
				
				file_name = f.getCanonicalPath().trim();
				
				if(!file_name.endsWith(File.separator))
					file_name = file_name + File.separator;
				
				fleOut = new File(file_name + File.separator + "data_export_" + driver.get_time_stamp_hyphenated() + ".txt");
				
				pwOut = new PrintWriter(new FileWriter(fleOut, true));
			}
			
			
			pwOut.println(this.jta.getText());
			pwOut.flush();
			pwOut.close();
			
			//driver.sound.play(ThreadSound.url_file_sent);
			driver.directive("If successful, output file has been written to \"" + fleOut.getCanonicalPath() + "\"");
			
			//attempt to open
			driver.open_file(fleOut);
			
			return fleOut;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "export_data", e);
		}
		
		return null;
	}
	
	public boolean send()
	{
		try
		{
			line = this.jtf.getText();
			
			this.append(line);
			appendToHistory(line.trim());
			this.jtf.setText("");
			
			Start.std_in.determineCommand(line);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "send", e);
		}
		
		return false;
	}
	
	public boolean clear()
	{
		try
		{
			//
			//Reject if enabled
			//
			if(this.jcbRejectUpdate.isSelected())
				return true;
			
			this.jta.setText("");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "clear", e);
		}
		
		return false;
	}
	
	public boolean append(String line)
	{
		try
		{
			//
			//Reject if enabled
			//
			if(this.jcbRejectUpdate.isSelected())
				return true;
			
			this.jta.append(line + "\n");
			++lineCount;
			
			if(restrict_data_entries && lineCount > maxLineCount)
			{
				this.jta.replaceRange("", 0, (int)(jta.getDocument().getLength()/3));
				lineCount = 0;
			}
			
			if(this.jcbAutoScroll.isSelected())
			{
				try
				{
					this.jta.setCaretPosition(this.jta.getDocument().getLength());
				}
				catch(Exception e)
				{
					
				}
			}
			
			if(MAX_CHAR_LEN > 0 && this.jta.getText().length() > MAX_CHAR_LEN)
			{
				try	{	this.jta.replaceRange("",  0,  150000);	}	catch(Exception e){}
			}
			
			
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "append", e);
		}
		
		return false;
	}
	
	public boolean prepend(String line)
	{
		try
		{
			try	{	this.jta.getDocument().insertString(0,  line + "\n",  null);	}	catch(Exception e)	{this.append(line + "\n");	}
			++lineCount;
			
			if(lineCount > maxLineCount)
			{
				this.jta.replaceRange("", 0, (int)(jta.getDocument().getLength()/3));
				lineCount = 0;
			}
			
			if(this.jcbAutoScroll.isSelected())
			{
				try
				{
					this.jta.setCaretPosition(0);
				}
				catch(Exception e)
				{
					
				}
			}
			
			//appendToHistory(line);
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "prepend", e);
		}
		
		return false;
	}
	
	/**no crlf added to end the line*/
	public boolean append_sp(String line)
	{
		try
		{
			//
			//Reject if enabled
			//
			if(this.jcbRejectUpdate.isSelected())
				return true;
			
			this.jta.append(line);		
			
			if(restrict_data_entries && lineCount > maxLineCount)
			{
				this.jta.replaceRange("", 0, (int)(jta.getDocument().getLength()/3));
				lineCount = 0;
			}
			
			if(this.jcbAutoScroll.isSelected())
			{
				try
				{
					this.jta.setCaretPosition(this.jta.getDocument().getLength());
				}
				catch(Exception e)
				{
					
				}
			}
			
			if(this.jta.getText().length() > 4000000)
			{
				try	{	this.jta.replaceRange("",  0,  150000);	}	catch(Exception e){}
			}
			
			
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "append_sp", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	

	
	@Override
	public void keyReleased(KeyEvent arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void keyTyped(KeyEvent arg0) {
		// TODO Auto-generated method stub
		
	}
	
	public void keyPressed(KeyEvent e) 
	{
	   switch( e.getKeyCode() ) 
	   { 
	        case KeyEvent.VK_UP:
	        {
	        	if(e.getSource() == this.jtf)
	        	{
	        		if(++history_index >= this.history.size())
	        			history_index = 0;
	        		
	        		try	{	this.jtf.setText(this.history.get(history_index));	}	catch(Exception ee){}
	        	}
	        	
	        	break;
	        }
	           
	        case KeyEvent.VK_DOWN:
	        {
	        	if(e.getSource() == this.jtf)
	        	{
	        		if(--history_index < 0)
	        			history_index = this.history.size()-1;
	        		
	        		try	{	this.jtf.setText(this.history.get(history_index));	}	catch(Exception ee){}
	        	}
	        	
	        	break;
	        }
	        case KeyEvent.VK_LEFT:
	        {
	        	break;
	        }
	        case KeyEvent.VK_RIGHT :
	        {
	        	break;
	        }
	     }
	} 
	
	
	
	public boolean appendToHistory(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return false;
			
			if(line.trim().equalsIgnoreCase("cls") || line.trim().equalsIgnoreCase("clr") || line.trim().equalsIgnoreCase("clear"))
				return true;
			
			if(this.history.size() < this.MAX_HISTORY_COUNT)
			{
				if(!history.contains(line))
					history.add(line);
				
				return true;
			}
			
			if(++history_index >= this.MAX_HISTORY_COUNT)
				history_index = 0;
						
			if(history_index < 0)
				history_index = this.history.size();
			
			if(!history.contains(line))
				history.set(history_index, line);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "appendToHistory", e);
		}
		
		return false;
	}

	
	
	
	
	
	
	
	
}
