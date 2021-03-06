package Driver;


import java.io.*;

import Interface.Interface;
import Interface.DEPRECATED_Interface;
import ServerSocket_Client.*;
import Worker.ThdWorker;

public class Start extends Thread implements Runnable
{
	public static final String myClassName = "Start";
	public static volatile Driver driver = new Driver();
	
	public static volatile StandardInListener std_in = null;
	public static volatile PrintWriter pwOut = null;
	public static volatile BufferedReader brIn = null;
	
	public static volatile ServerSocket_Client svr_skt_client = null;
	public static volatile ThdWorker thd_worker = null;
	
	public static String [] args = null;
	
	public static File fleConfigDirectory = null;
	public static String path_fleConfigDirectory = "";
	
	public static File fleConfig = null;	
	
	public static File fleMemoryAcquisitionDirectory = null;
	public static String path_fleMemoryAcquisitionDirectory = "";
	
	public static File fleExportMemoryAnalysisDirectory = null;
	public static String path_fleExportMemoryAnalysisDirectory = "";
	
	public static File fleImportMemoryAnalysisDirectory = null;
	public static String path_fleImportMemoryAnalysisDirectory = "";
	
	public static File fleImportMemoryImageDirectory = null;
	public static String path_fleImportMemoryImageDirectory = "";
	
	public static File fleExportDirectory = null;
	public static String path_fleExportDirectory = "";
	
	
	
	public static PrintWriter pwOut_config_file = null;
	
	
	public static volatile Interface intface = null;
	
	
	
	
	
	public Start(String [] argv)
	{
		try
		{
			args = argv;
			
			this.start();
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
			initialize_program();
			ensure_directory_configuration();
			analyze_args(args);							
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
		
	}
	
	
	
	public boolean initialize_program()
	{
		try
		{
			//place initialiation steps here if necessary
			brIn = new BufferedReader(new InputStreamReader(System.in));
			pwOut = new PrintWriter(new OutputStreamWriter (System.out));
						
			//
			//handle procuring additional input from user here...
			//
			
			
			
			//
			//Start the StandardInListener thread
			//
			std_in = new StandardInListener(brIn, pwOut);
			
			//
			//Server Socket
			//
			svr_skt_client = new ServerSocket_Client(ServerSocket_Client.DEFAULT_CLIENT_PORT);
			
			//
			//ThdWorker
			//
			thd_worker = new ThdWorker();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_program", e);
		}
		
		return false;
	}
	
	public boolean analyze_args(String [] arg)
	{
		try
		{
			if(arg == null || arg.length < 1)
			{
				//driver.directive("NULL VALUES!");
				intface = new Interface();
			}
			else
			{
				//
				//NOTIFY USER
				//
				driver.directive("///////////////////////////////////////////////////////////////////////////////////");
				driver.directive("// Welcome to " + Driver.FULL_NAME + " by Solomon Sonya @Carpenter1010\t//");
				driver.directive("/////////////////////////////////////////////////////////////////////////////////\n");
				
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_args", e);
		}
		
		return false;
	}
	
	
	
	
	public static boolean populate_config_file(File fle)
	{
		try
		{
			if(pwOut_config_file != null)
			{
				try	{	pwOut.close();} catch(Exception e){}
			}
			
			pwOut_config_file = new PrintWriter(new FileWriter(fle), true);
			
			pwOut_config_file.println("#####################################################################################");
			pwOut_config_file.println("#### Welcome to " + Driver.FULL_NAME + " by Solomon Sonya @Carpenter1010 \t\t ####"); 
			pwOut_config_file.println("#####################################################################################");
			
			pwOut_config_file.println("\n# NOTE 1: Remove the hash tag to enable a command input line");
			pwOut_config_file.println("# NOTE 2: Commands are in the format [cmd <tab> parameters]  \n# thus use tabs between the command and input to be read.");
			
			pwOut_config_file.println("\n# Socket Connection to Excalibur IDS");
			pwOut_config_file.println("#excalibur_ids	localhost 9700\n");
			
			
			
			try	{	 pwOut_config_file.flush();}catch(Exception e){}
			try	{	 pwOut_config_file.close();}catch(Exception e){}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_config_file", e);
		}
		
		return false;
	}
	
	public static boolean ensure_directory_configuration()
	{
		try
		{
			//
			//CONFIG FILE
			//
			
			/*if(fleConfigDirectory == null || !fleConfigDirectory.exists() || !fleConfigDirectory.isDirectory())
			{
				fleConfigDirectory = new File(Driver.NAME_LOWERCASE + File.separator + "import" + File.separator + "config");
				
				try	{	fleConfigDirectory.mkdirs();	}	 catch(Exception e){}
				
				if(fleConfigDirectory.getCanonicalPath().trim().endsWith(File.separator))
					path_fleConfigDirectory = fleConfigDirectory.getCanonicalPath().trim();
				else
					path_fleConfigDirectory = fleConfigDirectory.getCanonicalPath().trim() + File.separator;
				
				try
				{
					fleConfig = new File(path_fleConfigDirectory + "xavier.conf");
				}
				catch(Exception e)
				{
					fleConfig = new File(path_fleConfigDirectory + "xavier" + driver.get_time_stamp("_") + ".conf");
				}
				
				populate_config_file(fleConfig);
			}
			
			if(fleConfig == null || !fleConfig.exists() || !fleConfig.isFile())
			{
				try
				{
					fleConfig = new File(path_fleConfigDirectory + "xavier.conf");
				}
				catch(Exception e)
				{
					fleConfig = new File(path_fleConfigDirectory + "xavier" + driver.get_time_stamp("_") + ".conf");
				}
				
				populate_config_file(fleConfig);
			}*/
			
			//
			//IMPORT --> MEMORY IMAGE
			//
			if(fleImportMemoryImageDirectory == null || !fleImportMemoryImageDirectory.exists() || !fleImportMemoryImageDirectory.isDirectory())
			{
				fleImportMemoryImageDirectory = new File(Driver.NAME_LOWERCASE + File.separator + "import" + File.separator + "memory_image");
				
				try	{	fleImportMemoryImageDirectory.mkdirs();	}	 catch(Exception e){}
				
				if(fleImportMemoryImageDirectory.getCanonicalPath().trim().endsWith(File.separator))
					path_fleImportMemoryImageDirectory = fleImportMemoryImageDirectory.getCanonicalPath().trim();
				else
					path_fleImportMemoryImageDirectory = fleImportMemoryImageDirectory.getCanonicalPath().trim() + File.separator;
			}
			
			//
			//IMPORT --> MEMORY ANALYSIS
			//
			if(fleImportMemoryAnalysisDirectory == null || !fleImportMemoryAnalysisDirectory.exists() || !fleImportMemoryAnalysisDirectory.isDirectory())
			{
				fleImportMemoryAnalysisDirectory = new File(Driver.NAME_LOWERCASE + File.separator + "import" + File.separator + "memory_analysis");
				
				try	{	fleImportMemoryAnalysisDirectory.mkdirs();	}	 catch(Exception e){}
				
				if(fleImportMemoryAnalysisDirectory.getCanonicalPath().trim().endsWith(File.separator))
					path_fleImportMemoryAnalysisDirectory = fleImportMemoryAnalysisDirectory.getCanonicalPath().trim();
				else
					path_fleImportMemoryAnalysisDirectory = fleImportMemoryAnalysisDirectory.getCanonicalPath().trim() + File.separator;
			}
			
			//
			//IMPORT --> MEMORY ACQUISITION
			//
			/*if(fleMemoryAcquisitionDirectory == null || !fleMemoryAcquisitionDirectory.exists() || !fleMemoryAcquisitionDirectory.isDirectory())
			{
				fleMemoryAcquisitionDirectory = new File(Driver.NAME_LOWERCASE + File.separator + "import" + File.separator + "memory acquisition");
				
				try	{	fleMemoryAcquisitionDirectory.mkdirs();	}	 catch(Exception e){}
				
				if(fleMemoryAcquisitionDirectory.getCanonicalPath().trim().endsWith(File.separator))
					path_fleMemoryAcquisitionDirectory = fleMemoryAcquisitionDirectory.getCanonicalPath().trim();
				else
					path_fleMemoryAcquisitionDirectory = fleMemoryAcquisitionDirectory.getCanonicalPath().trim() + File.separator;
			}*/
			
			if(fleExportDirectory == null || !fleExportDirectory.exists() || !fleExportDirectory.isDirectory())
			{
				fleExportDirectory = new File(Driver.NAME_LOWERCASE + File.separator + "export");
				
				try	{	fleExportDirectory.mkdirs();	}	 catch(Exception e){}
				
				if(fleExportDirectory.getCanonicalPath().trim().endsWith(File.separator))
					path_fleExportDirectory = fleExportDirectory.getCanonicalPath().trim();
				else
					path_fleExportDirectory = fleExportDirectory.getCanonicalPath().trim() + File.separator;
			}
			
			if(fleExportMemoryAnalysisDirectory == null || !fleExportMemoryAnalysisDirectory.exists() || !fleExportMemoryAnalysisDirectory.isDirectory())
			{
				fleExportMemoryAnalysisDirectory = new File(Driver.NAME_LOWERCASE + File.separator + "export" + File.separator + "memory_analysis");
				
				try	{	fleExportMemoryAnalysisDirectory.mkdirs();	}	 catch(Exception e){}
				
				if(fleExportMemoryAnalysisDirectory.getCanonicalPath().trim().endsWith(File.separator))
					path_fleExportMemoryAnalysisDirectory = fleExportMemoryAnalysisDirectory.getCanonicalPath().trim();
				else
					path_fleExportMemoryAnalysisDirectory = fleExportMemoryAnalysisDirectory.getCanonicalPath().trim() + File.separator;
			}
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ensure_directory_configuration", e);
		}
		
		return false;
	}
	
	

}
