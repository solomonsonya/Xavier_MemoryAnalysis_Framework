/**
 * plugin: handles
 * @author Solomon Sonya
 */
package Advanced_Analysis;

import Advanced_Analysis.*;
import Driver.*;
import Interface.*;
import Plugin.*;
import Worker.*;
import java.awt.event.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.LinkedList;
import java.util.TreeMap;

public class Node_Handle 
{
	public static final String myClassName = "Node_Handle";
	public static volatile Driver driver = new Driver();
	
	public volatile String offset = "";
	public volatile int PID = -1;
	public volatile String handle_value = "";
	public volatile String access_value = "";
	public volatile String type = "";
	public volatile String details = "";
	
	public volatile Node_Process process = null;
	
	
	public Node_Handle()
	{
		try
		{
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public String toString()
	{
		try
		{
			return "details: " + details + "\ttype: " + type + "\taccess: " + access_value + "\thandle: " + handle_value + "\tpid: " + PID + "\toffset: " + offset ;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		return ".*..*";
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}


