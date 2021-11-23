/**
 * Pass components standard across all advanced analysis plugins
 * @Solomon Sonya
 */

package Advanced_Analysis.Analysis_Plugin;

import java.io.*;

import Driver.*;
import Interface.*;


public class _Analysis_Plugin_Super_Class extends Thread implements Runnable
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "_Analysis_Plugin_Super_Class";
	
	public volatile boolean EXECUTION_STARTED = false;
	public volatile boolean EXECUTION_COMPLETE = false;
	public volatile File fleOutput = null;
	public volatile File fle_import = null;
	
	public String EXECUTION_TIME_STAMP = driver.getTime_Specified_Hyphenated_with_seconds_using_colon(System.currentTimeMillis());
	
	public volatile File fle_volatility = null;
	public volatile File fle_memory_image = null;
	public volatile String PROFILE = Interface.PROFILE;
	public volatile String path_fle_analysis_directory = "";
	public volatile FileAttributeData file_attr_volatility = null;  
	public volatile FileAttributeData file_attr_memory_image = null;
	public volatile String investigator_name = "";
	public volatile String investigation_description = "";
	
	public volatile String plugin_name = "";
	public volatile String plugin_description = "";
	
	/** to identify multiple threads of the same plugin e.g. impacsn [272], impscan[688], etc*/
	public volatile String plugin_special_identifer = null;
	
	public _Analysis_Plugin_Super_Class()
	{
		try
		{
			
		}
		catch(Exception e)
		{
			
		}
	}

	
	
	
	
	public boolean write_process_header(PrintWriter pw, String plugin_name, String plugin_description, String execution_command)
	{
		try
		{
			return driver.write_process_header(investigator_name, investigation_description, EXECUTION_TIME_STAMP, file_attr_volatility, file_attr_memory_image, fle_memory_image, pw, plugin_name, plugin_description, execution_command);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_process_header", e);
		}
		
		return false;
	}
	
	
	/**
	 * used in ThdWorker to return special plugin names e.g. impscan  - [272], impscan - [688], or just the plugin name if it does not exist
	 * */
	public String get_plugin_special_identifier()
	{
		try
		{
			if(plugin_special_identifer != null)
				return plugin_special_identifer;
		}
		catch(Exception e)
		{
			
		}
		
		return plugin_name;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
