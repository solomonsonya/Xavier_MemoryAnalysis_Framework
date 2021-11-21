package Driver;

/**
 * @author Solomon Sonya
 * 
 * This code is adapted from my previous project, Excalibur TIE
 */


import java.util.*;
import java.awt.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.TimeZone;
import java.util.UUID;
import java.util.Vector;
import java.security.*;
import java.sql.Connection;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;



public class Time 
{
	public static final String myClassName = "Time";
	public Driver driver = new Driver();
	
	public static final String [] months = new String[]{"january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"};
	public static final LinkedList<String> list_months = new LinkedList<String>(Arrays.asList(months));
	public volatile static String day = "", mon = "", year = "";
	public volatile static String [] date = null, month_split = null;
	
	public static volatile String mon_partial = "", day_partial = "";
	public static volatile int month_index = 1;

	public static final long start_time = System.currentTimeMillis();
	
	
	public Time (){}//null constructor
	
		
	/**
	 * yyyy-MM-dd-HHmm
	 * @return
	 */
	public String getTime_Current_Hyphenated()
	{
		try
		{
			DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd-HHmm");
			dateFormat.setLenient(false);
			
			Date dateTime = new Date();
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
		
		try
		{
			return getTime_Specified_Hyphenated(getTime_Current_Millis());
		}
		catch(Exception e)
		{
			
		}
		return "";
	}
	
	/**
	 * yyyy-MM-dd-HHmm
	 * @return
	 */
	public String getTime_Current_Hyphenated(boolean include_semi_colon_between_hours_and_mins)
	{
		try
		{
			DateFormat dateFormat = null;
			
			if(include_semi_colon_between_hours_and_mins)
				dateFormat = new SimpleDateFormat("yyyy-MM-dd-HH:mm");
			else
				dateFormat = new SimpleDateFormat("yyyy-MM-dd-HHmm");
			
			dateFormat.setLenient(false);
			
			Date dateTime = new Date();
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
		
		try
		{
			return getTime_Specified_Hyphenated(getTime_Current_Millis());
		}
		catch(Exception e)
		{
			
		}
		return "";
	}
	
	public String upTime()
	{
		try
		{
			//return getTimeInterval(System.currentTimeMillis(), this.start_time);
			return "STARTED: " + getTime_Specified_Hyphenated(start_time) + "\t UP TIME: " +  this.getTimeInterval_WithDays(System.currentTimeMillis(), this.start_time);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "upTime", e);
		}
		
		return "invalid time specification in Time...";
	}
	
	/**
	 * 
	 * @return
	 */
	public String getTime_Current_Underscored(boolean include_secs)
	{
		try
		{
			DateFormat dateFormat = null;
			
			if(include_secs)
				dateFormat = new SimpleDateFormat("yyyy_MM_dd_HH_mm_ss");
			else			
				dateFormat = new SimpleDateFormat("yyyy_MM_dd_HH_mm");
			
			dateFormat.setLenient(false);
			
			Date dateTime = new Date();
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
		
		try
		{
			return getTime_Specified_Hyphenated(getTime_Current_Millis());
		}
		catch(Exception e)
		{
			
		}
		return "";
	}
	
	
	public String getTime_Current(String delimiter, boolean include_secs)
	{
		try
		{
			DateFormat dateFormat = null;
			
			if(include_secs)
				dateFormat = new SimpleDateFormat("yyyy" + delimiter + "MM" + delimiter + "dd" + delimiter + "HH" + "mm" + delimiter + "ss");
			else			
				dateFormat = new SimpleDateFormat("yyyy" + delimiter + "MM" + delimiter + "dd" + delimiter + "HH" + "mm");
			
			dateFormat.setLenient(false);
			
			Date dateTime = new Date();
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
		
		try
		{
			return getTime_Specified_Hyphenated(getTime_Current_Millis());
		}
		catch(Exception e)
		{
			
		}
		return "";
	}
	
	public String getTime_Current_hyphenated_with_seconds(String delimiter)
	{
		try
		{
			DateFormat dateFormat = null;
			
			dateFormat = new SimpleDateFormat("yyyy" + delimiter + "MM" + delimiter + "dd" + delimiter + "HH" + "mm" + ":" + "ss");
			
			
			dateFormat.setLenient(false);
			
			Date dateTime = new Date();
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
		
		try
		{
			return getTime_Specified_Hyphenated(getTime_Current_Millis());
		}
		catch(Exception e)
		{
			
		}
		return "";
	}
	
	/**
	 * yyyy_MM_dd
	 * @return
	 */
	public  String getDate_Current_Underscored()
	{
		try
		{
			DateFormat dateFormat = new SimpleDateFormat("yyyy_MM_dd");
			dateFormat.setLenient(false);
			
			Date dateTime = new Date();
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
		
		try
		{
			return getTime_Specified_Hyphenated(getTime_Current_Millis());
		}
		catch(Exception e)
		{
			
		}
		return "";
	}
	
	/**
	 * yyyy-MM-dd
	 * @return
	 */
	public  String getDate_Current_Hyphenated()
	{
		try
		{
			DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
			dateFormat.setLenient(false);
			
			Date dateTime = new Date();
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
		
		try
		{
			return getTime_Specified_Hyphenated(getTime_Current_Millis());
		}
		catch(Exception e)
		{
			
		}
		return "";
	}
	
	public  String getYear_ONLY()
	{
		try
		{
			DateFormat dateFormat = new SimpleDateFormat("yyyy");
			dateFormat.setLenient(false);
			
			Date dateTime = new Date();
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("getYear_ONLY -- Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
				
		return "";
	}
	
	public  String getTimeInterval_WithDays(long currTime_millis, long prevTime_millis)
	{
		String timeInterval = "UNKNOWN";
		try
		{
			SimpleDateFormat dateFormat = new SimpleDateFormat("DD:HH:mm:ss");
			dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
			
			//long currTime_millis = System.currentTimeMillis();//get the current time in milliseconds
			
			long interval = currTime_millis - prevTime_millis;
			
			timeInterval = dateFormat.format(new Date(interval));		
			
		}
		catch(Exception e)
		{
			System.out.println("Error caught in calculateTimeInterval_From_Present_Time mtd");
		}
		
		return timeInterval;
	}
	
	public  String getMon_ONLY()
	{
		try
		{
			DateFormat dateFormat = new SimpleDateFormat("MM");
			dateFormat.setLenient(false);
			
			Date dateTime = new Date();
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("getMon_ONLY -- Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
				
		return "";
	}
	
	public  String getDay_ONLY()
	{
		try
		{
			DateFormat dateFormat = new SimpleDateFormat("dd");
			dateFormat.setLenient(false);
			
			Date dateTime = new Date();
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("getDay_ONLY -- Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
				
		return "";
	}
	
	public  String getTime_ONLY()
	{
		try
		{
			DateFormat dateFormat = new SimpleDateFormat("HH:mm");
			dateFormat.setLenient(false);
			
			Date dateTime = new Date();
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("getTime_ONLY -- Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
				
		return "";
	}
	
	public  String getTime_With_Seconds_ONLY()
	{
		try
		{
			DateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
			dateFormat.setLenient(false);
			
			Date dateTime = new Date();
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("getTime_With_Seconds_ONLY -- Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
				
		return "";
	}
	
	public  long getTime_Current_Millis()	{	try	{	return System.currentTimeMillis();	}	catch(Exception e){} return 1;}
	
	public  String getTime_Specified_Hyphenated(long time_millis)
	{
		try
		{
			DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd-HHmm");
			dateFormat.setLenient(false);
			
			Date dateTime = new Date(time_millis);
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
		
		return "";
	}
	
	public  String getTime_Specified_Hyphenated(String date_yyyyMMdd)
	{
		try
		{
			DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd-HHmm");
			dateFormat.setLenient(false);
			
			Date dateTime = dateFormat.parse(date_yyyyMMdd);
			
			return dateFormat.format(dateTime);
		}
		catch(Exception e)
		{
			driver.sop("Invalid date specified - - - " + date_yyyyMMdd + " is not a proper date selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
		
		return "";
	}
	
	public  long getTime_Specified_Millis(String date_yyyyMMdd)
	{
		try
		{
			DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
			dateFormat.setLenient(false);
			
			Date dateTime = dateFormat.parse(date_yyyyMMdd);
			
			return dateTime.getTime();
		}
		catch(Exception e)
		{
			driver.sop("Invalid date specified - - - -" + date_yyyyMMdd + " is not a proper date selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
		
		return 0;
	}
	
	/**
	 * This method calculates the time difference between the string time passed in (in milliseconds) and the current system time
	 */
	public  String getTimeInterval(long currTime_millis, long prevTime_millis)
	{
		String timeInterval = "UNKNOWN";
		try
		{
			SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
			dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
			
			//long currTime_millis = System.currentTimeMillis();//get the current time in milliseconds
			
			long interval = currTime_millis - prevTime_millis;
			
			timeInterval = dateFormat.format(new Date(interval));		
			
		}
		catch(Exception e)
		{
			System.out.println("Error caught in calculateTimeInterval_From_Present_Time mtd");
		}
		
		return timeInterval;
	}
	
	/**
	 * This method returns the current time stamp for this system's time clock in the format: 2013, 11, 16, 00, 02
	 */
	public  String getTimeStamp_CSV()
	{
		
		Date dateTime;// = new Date();//get the current date, time, timezone  //  @jve:decl-index=0:
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy, MM, dd, HH, mm");
		
		//Get the Date
		dateTime = new Date();//must always re-init in order to get the curr date and time
		
		try
		{	
			
			return dateFormat.format(dateTime);
			
			
		}//end try
		catch(Exception e)//incase an error is generated from the above parse of the time and date, simply display the generic date for the client
		{
			driver.sop("Time Exception in Drivers!!!!!!!");
			
			//go to the old way for calling the Rime:
			try
			{				
				return getTimeStamp_Without_Date();
			}
			catch(Exception ee)
			{
				//all else failed, just return the time
				return dateTime.toString();
			}
			
		}
		
			
	}
	
	/**
	 * This method returns the current time stamp for this system's time clock in the format: Sat - 12 Jul 2008 - 15:48 "13 - Eastern
	 */
	public  String getTimeStamp__With_Hour_Hyphenated()
	{
		
		Date dateTime;// = new Date();//get the current date, time, timezone  //  @jve:decl-index=0:
		String timeToSplit = "";
		String [] arrSplitTime;
		//SimpleDateFormat dateFormat = new SimpleDateFormat("EE - dd MMM yyyy - HH:mm \"ss - zzzz");
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd-HHmm");
		String [] arrSplitTimeZone;
		String [] arrSplitDate;
		String dateTime_To_Display = "";  //  @jve:decl-index=0:
		//Get the Date
		dateTime = new Date();//must always re-init in order to get the curr date and time
		

		
		try
		{	

			//Get the formatted string from the date: in form of "Wed - 01 Oct 08 - 00:36 "28 - Central Daylight Time"
			timeToSplit = dateFormat.format(dateTime);
			
			arrSplitTime = timeToSplit.split("-");//return an array delimeted with Day of the Week, Date, Time, Time Zone
			
			//Note: we don't to display the entire time zone text, i.e. if time zone is Central Daylight Time, we only want Central to show, therefore split the last token in arrSplitTime and return only the first word
			arrSplitTimeZone = (arrSplitTime[3]).split(" ");

			//		 DAY OF WEEK		-	   DAY MON YEAR			 -		TIME		   -		TIME ZONE		
			//return (arrSplitTime[0] + " - " + arrSplitTime[1] + " - " + arrSplitTime[2] + "- " + arrSplitTimeZone[1] + "         ");
			
			//arrSplitDate = arrSplitTime[1].split(" ");
			return dateFormat.format(dateTime);
			
			
		}//end try
		catch(Exception e)//incase an error is generated from the above parse of the time and date, simply display the generic date for the client
		{
			//go to the old way for calling the Rime:
			try
			{
				return getTimeStamp_Without_Date();
			}
			catch(Exception ee)
			{
				//all else failed, just return the time
				return dateTime_To_Display = "Time: " + dateTime.toString();
			}
			
		}
		
		//return dateTime_To_Display;		
	}
	
	/**
	 * This method just returns the current system clock time in the format HH:MM "SS
	 */
	public  String getTimeStamp_Without_Date()
	{
		Date dateTime;// = new Date();//get the current date, time, timezone  //  @jve:decl-index=0:

		String timeToSplit = "";
		String dateTime_To_Display = "";  //  @jve:decl-index=0:
		String [] arrSplitTime;
		String [] arrSplitHour;
		String strHourMin = "";
		
		dateTime = new Date();
		
		try
		{	
			timeToSplit = dateTime.toString();
						
			arrSplitTime = timeToSplit.split(" ");//return an array with Day_Name Mon Day_Num HH:MM:SS LocalTime YYYY
						
			if(arrSplitTime.length != 6)//ensure array was split properly; if it's length is not 6, then an error occurred, so just show the simple time by throwing the exception
				throw new Exception();
			
			arrSplitHour = (arrSplitTime[3]).split(":");
			
			if(arrSplitHour.length != 3)//again, ensure we split the time from 18:57:48 bcs we only want 18:57
				throw new Exception();
			
			return strHourMin = arrSplitHour[0] + ":" + arrSplitHour[1] + " \"" + arrSplitHour[2];  
			
			
		}//end try
		catch(Exception e)//incase an error is generated from the above parse of the time and date, simply display the generic date for the client
		{
			dateTime_To_Display = "Time: " + dateTime.toString();
		}
		
		return dateTime_To_Display;		
	}//end mtd getTimeStamp
	
	public  String getTimeStamp_ZULU()
	{
		try
		{
			Date dateTime;// = new Date();//get the current date, time, timezone  //  @jve:decl-index=0:
			SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
			dateFormat.setTimeZone(TimeZone.getTimeZone("Zulu"));
			
			dateTime = new Date();//must always re-init in order to get the curr date and time
			
			return dateFormat.format(dateTime);			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getTimeStamp_ZULU", e);
		}
		
		return "00:00:00";
	}
	
	/**
	 * Return time as
	 * [0] = yyyy
	 * [1] = MM
	 * [2] = dd
	 * [3] = HH
	 * [4] = mm
	 * @param time_millis
	 * @return
	 */
	public  LinkedList<String> getTime_Specified_As_ArrayList(long time_millis)
	{
		try
		{
			DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd-HH-mm");
			dateFormat.setLenient(false);
			
			Date dateTime = new Date(time_millis);
			
			String []arrTime = null;
			LinkedList<String>alTime = new LinkedList<String>();
			
			try
			{
				arrTime = dateFormat.format(dateTime).split("-");
				
				alTime.add("" + arrTime[0]); //YEAR
				alTime.add("" + arrTime[1]); //MON
				alTime.add("" + arrTime[2]); //DAY
				alTime.add("" + arrTime[3]); //HOUR
				alTime.add("" + arrTime[4]); //MIN
				
				
			}
			catch(Exception e)
			{				
				arrTime = dateFormat.format(new Date(System.currentTimeMillis())).split("-");
				
				alTime.add("" + arrTime[0]); //YEAR
				alTime.add("" + arrTime[1]); //MON
				alTime.add("" + arrTime[2]); //DAY
				alTime.add("" + arrTime[3]); //HOUR
				alTime.add("" + arrTime[4]); //MIN
			}
			
			
			
			return alTime;
		}
		catch(Exception e)
		{
			driver.sop("Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
		
		return null;
	}
	
}
