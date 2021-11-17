/**
 * Create a File and PrintWriter object
 * @author Solomon Sonya
 */

package Driver;

import java.io.*;

public class FilePrintWriter extends File
{
	public static final String myClassName = "FilePrintWriter";
	public static Driver driver = new Driver();
	public File fle = null;
	public File fleOutputDirectory = null;
	public PrintWriter pwOut = null;
	
	public FilePrintWriter(String file_name)
	{
		super(file_name);
		
		try
		{
			fle = new File(file_name);
			
			if(fle != null)
			{
				fleOutputDirectory = fle.getParentFile();
				
				if(!fleOutputDirectory.exists())
					fleOutputDirectory.mkdirs();
				
				pwOut = new PrintWriter(new FileWriter(fle), true);
			}
			
		}
		catch(FileNotFoundException fne)
		{
			//certain file names are reserved even with an extension. e.g. con, prn, aux, nul, etc... thus, we cannot create even a file called con.txt
			//if so, we'd expect a file not found exception. 
			//here, let's create a new file based on this exception
			
			try
			{
				if(file_name != null)
				{														
					String name =  file_name.substring(file_name.trim().lastIndexOf(File.separator)+1);					
					
					String [] array = name.split("\\.");
					
					name = array[0] + "_." + array[1].trim(); 
					
					String path = fleOutputDirectory.getCanonicalPath().trim();
					if(!path.endsWith(File.separator))
						path = path + File.separator;									
					
					fle = new File(path + name);
					
					fleOutputDirectory = fle.getParentFile();
					
					if(!fleOutputDirectory.exists())
						fleOutputDirectory.mkdirs();
					
					pwOut = new PrintWriter(new FileWriter(fle), true);
				}
			}
			catch(Exception ee)
			{
				//driver.eop(myClassName, "Constructor - value 2", ee);
			}
		
			
		}
		catch(Exception e)
		{			
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public boolean print(String out)
	{
		try
		{
			this.pwOut.print(out);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print", e);
		}
		
		return false;
	}
	
	public boolean println(String line)
	{
		try
		{
			this.pwOut.println(line);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "println", e);
		}
		
		return false;
	}
	
	public boolean flush()
	{
		try
		{
			this.pwOut.flush();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "flush", e);
		}
		
		return false;
	}
	
	public boolean close()
	{
		try
		{
			this.pwOut.close();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "close", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
}
