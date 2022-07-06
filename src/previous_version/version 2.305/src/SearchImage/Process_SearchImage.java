package SearchImage;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.*;
import java.util.*;
import java.util.LinkedList;


import Driver.Driver;
import Driver.FileAttributeData;
import Interface.Interface;
import Interface.JTextArea_Solomon;

public class Process_SearchImage extends Thread implements Runnable 
{
	public static final String myClassName = "Process_SearchImage";
	public static volatile Driver driver = new Driver();
	
	public static final int MAX_BYTES_TO_READ = 4096;
	public volatile File fle = null;
	public String []keywords = null;
	public SearchImage parent = null;
	public volatile boolean STOP = false;
	public volatile FileAttributeData attribute = null;
	public volatile boolean updated_attributes = false;
	public String keys = ""; 
	public volatile File fle_out = null;
	public volatile boolean include_full_context_around_keyword_hit = false;
	
	
	public Process_SearchImage(SearchImage par, File file, String [] KEYWORDS, String KEYS, FileAttributeData attr, boolean Include_full_context_around_keyword_hit)
	{
		try
		{
			fle = file;
			keywords = KEYWORDS;
			keys = KEYS;
			parent = par;
			attribute = attr;
			include_full_context_around_keyword_hit = Include_full_context_around_keyword_hit;
			
			if(attribute == null)
				attribute = new FileAttributeData(fle, true, true);
			
			if(fle != null && fle.exists() && fle.isFile() && keywords != null && keywords.length > 0)
			{
				this.start();
			}
			else
			{
				driver.directive("Unable to commenct search through image. Either file or keywords are invalid...");
			}
			
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
			commence_search("\t");			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	
	public boolean commence_search(String delimiter)
	{
		try
		{
			//open the file
			InputStream fis = new FileInputStream(fle);
			byte [] buffer = new byte[MAX_BYTES_TO_READ];
			int bytes_read = 0;
			
			long total_bytes_read = 0;
			long overflow = 0;
			long hits = 0;
			long hits_overflow = 0;
			int i = 0;
			
			fle_out = new File("./xavier_framework/export/memory_analysis/" + Interface.analysis_time_stamp + "/search/search_" + fle.getName() + "_" + driver.get_time_stamp("_") + ".txt");
			
			try	{	fle_out.getParentFile().mkdirs();	}	 catch(Exception e){}
			
			PrintWriter pwOut = new PrintWriter(new FileWriter(fle_out), true);
			
			pwOut.println("Image File --> " + fle.getCanonicalPath());
			pwOut.println("Search keywords --> " + keys + "\n");
			
			sop("Commencing search actions on image file --> " + fle.getCanonicalPath());
			sop("Search keywords --> " + keys + "\n");
			String line = "";
			String [] array = null;					
			
			while((bytes_read = fis.read(buffer)) > 0)
			{
				if(STOP)
				{
					sop("\n\n##############################################################");
					sop("# STOP COMMAND RECEIVED! Halting search actions here...");
					sop("##############################################################");
					break;
				}				
				
				line = new String(buffer, 0, bytes_read);
				
				line = line.replaceAll("\n", " ");
				
				for(String token : this.keywords)
				{
					if(token == null || token.equals(""))
						continue;
					
					if(line.toLowerCase().contains(token))
					{
						if(include_full_context_around_keyword_hit)
						{
							//hit found!
							pwOut.println("offset: " + total_bytes_read + delimiter + line);
							sop("offset: " + total_bytes_read + delimiter + line);
							++hits;
						}
						else//restrict to first word found
						{
							array = line.split(" ");
							
							//save only the actual value without extra noise in the background
							for(String value : array)
							{
								if(value.toLowerCase().contains(token))
								{
									//hit found!
									pwOut.println("offset: " + total_bytes_read + delimiter + value);
									sop("offset: " + total_bytes_read + delimiter + value);
									++hits;
								}
								
								
							}
						}
						
						
						
						
						
						if(hits+100 >= Long.MAX_VALUE)
						{
							hits = 0;
							hits_overflow++;
						}
						
					}
				}
				
				
				if(total_bytes_read +MAX_BYTES_TO_READ + 9999 > Long.MAX_VALUE)
				{
					total_bytes_read = 0;
					++overflow;
				}
				
				total_bytes_read+= bytes_read;
				
				if((i++)%99999999 == 0)
				{
					i = 0;
					//sp(".");
					
					if(!updated_attributes && attribute.is_hashing_complete)
					{
						if(parent != null)
						{
							parent.jlblFileAttributes.setText("   " + attribute.get_attributes("\t  "));
							parent.jlblFileAttributes.setToolTipText(attribute.get_attributes("\t  "));
						}
						
						updated_attributes = true;
					}
						
				}
				
				
				
				
				
				
			}
			
			sp("\n");
			
			sop("Search complete. Total bytes read: " + driver.get_file_size(total_bytes_read));
			sop("Keyword Hits: [" + hits + "]");
			sop("Image Path: " + fle.getCanonicalPath());
			
			pwOut.println("\nSearch complete. Total bytes read: " + driver.get_file_size(total_bytes_read));
			pwOut.println("Keyword Hits: [" + hits + "]");
			pwOut.println("Image Path: " + fle.getCanonicalPath());
			
			
			if(attribute.is_hashing_complete)
			{
				pwOut.println("Image Attributes: " + attribute.get_attributes("\t  "));
				sop("Image Attributes: " + attribute.get_attributes("\t  "));
			}
			
			if(!updated_attributes && attribute.is_hashing_complete)
			{
				if(parent != null)
				{
					parent.jlblFileAttributes.setText("   " + attribute.get_attributes("\t  "));
					parent.jlblFileAttributes.setToolTipText(attribute.get_attributes("\t  "));
					//pwOut.println("\nFile Attributes: " + attribute.get_attributes("\t  "));
				}
				
				updated_attributes = true;
			}
			
			
			
			try	{	pwOut.flush();} catch(Exception e){}
			try	{	pwOut.close();} catch(Exception e){}
			
			
			return true;
		}
		catch(Exception e)
		{
			sop("PUNT! I was not able to commence search actions on file --> " + fle);
		}
		
		return false;
	}
	
	
	
	public boolean sop(String out)
	{
		try
		{						
			if(parent != null)
				parent.jta.append(out);
			else
				driver.sop(out);
			
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
			driver.sp(out);
			
			if(parent != null)
				parent.jta.append_sp(out);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sp", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
