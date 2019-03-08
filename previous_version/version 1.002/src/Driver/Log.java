package Driver;

/**
 * @author Solomon Sonya
 * */


import javax.swing.*;
import javax.swing.Timer;
import java.io.*;
import java.util.*;
import java.awt.event.*;


public class Log extends Thread implements Runnable, ActionListener
{
	public static final String myClassName = "Log";
	public static final String version_log = "1.002";
	
	public static volatile Driver driver = new Driver();
	
	private volatile LinkedList<String> queue = new LinkedList<String>();
	
	public static volatile boolean logging_enabled = true;
	
	public volatile String logging_path  = "path not set...";
	public static volatile String main_logging_path  = "path not set...";
	
	
	Timer tmr = null;
	public int millis_interrupt = 100;
	
	public volatile boolean handle_interrupt = true;
	
	public static volatile File fleMainLogDirectory = null;
	public volatile File fleLogDirectory = null;
	public volatile File fleLogFile = null;
	public volatile PrintWriter pwOut = null;
	
	public volatile String TOP_FOLDER_NAME = "";
	public volatile String TOP_FOLDER_PATH = "";
	public volatile String LOG_FILE_NAME = "";
	public volatile int MAX_LOG_SIZE_BYTES = -1;
	
	public static final String END_LOG_OPEN_FILE_DO_NOT_OPEN_WHEN_COMPLETE = "//SOLOMON_SONYA_end_LOG_OPEN_FILE_DO_NOT_OPEN_WHEN_COMPLETE//CARPENTER1010";
	public static final String END_LOG_OPEN_FILE_OPEN_WHEN_COMPLETE = "//SOLOMON_SONYA_end_LOG_OPEN_FILE_NOT_OPEN_WHEN_COMPLETE//CARPENTER1010";
	
	/**Indicate to log even if logging is disabled globally e.g. if we want to write out dns entries but not log all packets*/
	public volatile boolean OVERRIDE_LOGGING_ENABLED = false;
	
	public Log(String log_name, int interrupt_time, int max_log_size_bytes)
	{
		try
		{
			LOG_FILE_NAME = log_name;
			
			if(LOG_FILE_NAME == null || LOG_FILE_NAME.trim().equals(""))
				LOG_FILE_NAME = "log";
			
			millis_interrupt =  interrupt_time;
			
			if(millis_interrupt < 1)
				millis_interrupt = 1;
			
			MAX_LOG_SIZE_BYTES = max_log_size_bytes;
			
			ensure_logging_configuration(false);
			
			this.start();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public Log(String top_folder_name, String log_name, int interrupt_time, int max_log_size_bytes)
	{
		try
		{
			LOG_FILE_NAME = log_name;
			
			TOP_FOLDER_NAME = top_folder_name;
			
			if(LOG_FILE_NAME == null || LOG_FILE_NAME.trim().equals(""))
				LOG_FILE_NAME = "log";
			
			millis_interrupt =  interrupt_time;
			
			if(millis_interrupt < 1)
				millis_interrupt = 1;
			
			MAX_LOG_SIZE_BYTES = max_log_size_bytes;
			
			ensure_logging_configuration(false);
			
			this.start();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 2", e);
		}
	}
	
	public void run()
	{
		try
		{
			tmr = new Timer(millis_interrupt, this);
			tmr.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean display_status()
	{
		try
		{
			ensure_logging_configuration(false);
			driver.directive("[" + LOG_FILE_NAME.toUpperCase() + "] to location --> " + fleLogFile.getCanonicalPath());
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "display_status", e);
		}
		
		return false;
	}
	
	/**
	 * to bypass the queue
	 * @param line
	 * @return
	 */
	public boolean log_directly(String line)
	{
		try
		{						
			if(!logging_enabled && !OVERRIDE_LOGGING_ENABLED)
				return false;
			
			ensure_logging_configuration(false);
			
			this.pwOut.println(line);
			this.pwOut.flush();
			
			return true;
		}
		 catch(Exception e)
		{
			 driver.eop(myClassName, "log_directly", e);
		}
		
		return false;
	}
	
	public boolean log(String line)
	{
		try
		{
			if(this.logging_enabled)
				this.queue.addLast(line);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "log", e);
		}
		
		return false;
	}
	
	public static boolean toggle_logging()
	{
		try
		{
			Log.logging_enabled = !Log.logging_enabled;
			
			String path = "";
			
			if(Log.fleMainLogDirectory != null)
				path = Log.fleMainLogDirectory.getCanonicalPath();
			else
			{
				File fle = new File("./");
				path = fle.getCanonicalPath();
			}
			
			main_logging_path = path;
			
			if(Log.logging_enabled)
				driver.directive("\nLogging is enabled. Directory --> " + path);
			else
				driver.directive("\nLogging is disabled. Directory --> " + path);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toggle_logging", e);
		}
		
		return false;
	}
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == tmr && !queue.isEmpty())
			{
				process_interrupt();
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
		
	}
	
	public boolean ensure_logging_configuration(boolean verbose)
	{
		try
		{
			//
			//ensure log directory exists
			//
			if(fleLogDirectory == null || !fleLogDirectory.exists() || !fleLogDirectory.isDirectory())
			{
				fleLogDirectory = new File("./");
				
				fleMainLogDirectory = fleLogDirectory;
				
				if(fleLogDirectory.getCanonicalPath().endsWith(File.separator))
				{
					//check if there's an additional folder path
					if(TOP_FOLDER_NAME != null && !TOP_FOLDER_NAME.trim().equals(""))
						fleLogDirectory = new File(fleLogDirectory.getCanonicalPath() + Driver.NAME_LOWERCASE + File.separator + "log" + File.separator + TOP_FOLDER_NAME.trim());
					else
						fleLogDirectory = new File(fleLogDirectory.getCanonicalPath() + Driver.NAME_LOWERCASE + File.separator + "log");					
				}
				else
				{
					if(TOP_FOLDER_NAME != null && !TOP_FOLDER_NAME.trim().equals(""))
						fleLogDirectory = new File(fleLogDirectory.getCanonicalPath() + File.separator + Driver.NAME_LOWERCASE + File.separator + "log" + File.separator + TOP_FOLDER_NAME.trim());
					else
						fleLogDirectory = new File(fleLogDirectory.getCanonicalPath() + File.separator + Driver.NAME_LOWERCASE + File.separator + "log");
				}
				
				
				
				
				try	{	fleLogDirectory.mkdirs();	}	catch(Exception e){}
				
				TOP_FOLDER_PATH = fleLogDirectory.getCanonicalPath();
				
				if(verbose)
					driver.sop("Log file directory set to " + fleLogDirectory.getCanonicalPath());
			}
			
			//
			//ensure log file exists
			//
			if(this.fleLogFile == null || !fleLogFile.exists() || !fleLogFile.isFile())
			{
				if(fleLogDirectory.getCanonicalPath().endsWith(File.separator))
				{
					fleLogFile = new File(fleLogDirectory.getCanonicalPath() + this.LOG_FILE_NAME + "_" + driver.get_time_stamp("_") + ".txt");	
					pwOut = new PrintWriter(new FileWriter(fleLogFile), true);
					
					if(verbose)
						driver.sop("Log file created at " + fleLogFile.getCanonicalPath());
				}
				else
				{
					fleLogFile = new File(fleLogDirectory.getCanonicalPath() + File.separator + this.LOG_FILE_NAME + "_" + driver.get_time_stamp("_") + ".txt");	
					pwOut = new PrintWriter(new FileWriter(fleLogFile), true);
					
					if(verbose)
						driver.sop("Log file created at " + fleLogFile.getCanonicalPath());
				}
			}
			
			logging_path = fleLogFile.getCanonicalPath();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ensure_logging_configuration", e);
		}
		
		return false;
	}
	
	public boolean process_interrupt()
	{
		try
		{
			if(!logging_enabled)
				return false;
			
			if(!handle_interrupt)
				return true;
			
			if(this.queue.isEmpty())
				return true;
			
			handle_interrupt = false;
			
			ensure_logging_configuration(true);
			
						
			//
			//Write contents
			//
			//pwOut.println(this.queue.removeFirst());
			//pwOut.flush();
			
			//
			//check if there are any remaining contents in the queue, if so, exhaust queue here...
			//
			while(!queue.isEmpty())
			{
				if(queue.peek().equals(this.END_LOG_OPEN_FILE_DO_NOT_OPEN_WHEN_COMPLETE))
				{
					try {	this.queue.clear();	}	catch(Exception e){}
					pwOut.flush();
					try	{	pwOut.close();	}	catch(Exception e){}					
					try	{	this.tmr.stop();}	catch(Exception e){}
					
					logging_enabled = false;
					
					try	{	System.gc();	}	catch(Exception e){}
					
					//try to release resources
					try	{	this.tmr.stop();}	catch(Exception e){}
					//try	{	this.destroy();}	catch(Exception e){}
					
					//retain lock on semaphore
					return true;
				}
				
				else if(queue.peek().equals(this.END_LOG_OPEN_FILE_OPEN_WHEN_COMPLETE))
				{
					try {	this.queue.clear();	}	catch(Exception e){}
					pwOut.flush();
					try	{	pwOut.close();	}	catch(Exception e){}					
					try	{	this.tmr.stop();}	catch(Exception e){}
					
					logging_enabled = false;
					
					//attempt to open the file
					if(driver.isWindows && fleLogFile.exists())
					{
						try	{	Process p = Runtime.getRuntime().exec("explorer.exe " + fleLogFile.getCanonicalPath());	}	catch(Exception e){}
					}
					
					try	{	System.gc();	}	catch(Exception e){}
					
					//try to release resources
					try	{	this.tmr.stop();}	catch(Exception e){}
					//try	{	this.destroy();}	catch(Exception e){}
					
					//retain lock on semaphore
					return true;
				}
				
				//
				//otw, print!
				//				
				pwOut.println(this.queue.removeFirst());				
				pwOut.flush();
			}
			
			//
			//Check if max size reached
			//
			if(this.MAX_LOG_SIZE_BYTES > 0 && this.fleLogFile != null && this.fleLogFile.length() > this.MAX_LOG_SIZE_BYTES)
			{
				try	{	pwOut.flush();	}	catch(Exception e){}
				try	{	pwOut.close();	}	catch(Exception e){};
				
				//set to null so we know to allocate a new file
				fleLogFile = null;
			}
			
			handle_interrupt = true;
			return true;
		}
		catch(NoSuchElementException nse)
		{
			handle_interrupt = true;
			try	{	pwOut.flush();	}	catch(Exception ee){}
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_interrupt", e);
		}
		
		handle_interrupt = true;
		
		return false;
	}
	
	public boolean close_and_open_log_file()
	{
		try
		{
			try {	this.queue.clear();	}	catch(Exception e){}
			pwOut.flush();
			
			try	{	pwOut.close();	}	catch(Exception e){}					
			try	{	this.tmr.stop();}	catch(Exception e){}					
			
			//attempt to open the file
			if(driver.isWindows && fleLogFile.exists())
			{
				try	{	Process p = Runtime.getRuntime().exec("explorer.exe " + fleLogFile.getCanonicalPath());	}	catch(Exception e){}
			}
			
			try	{	System.gc();	}	catch(Exception e){}
			
			
			//retain lock on semaphore
			return true;
		}			
			
		catch(Exception e)
		{
			driver.eop(myClassName, "close_and_open_log_file", e);
		}
		
		return false;
	}

}
