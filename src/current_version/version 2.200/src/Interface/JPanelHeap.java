/**
 * @author Solomon Sonya
 */

package Interface;

import javax.swing.*;
import javax.swing.Timer;
import javax.swing.border.BevelBorder;
import Driver.*;
//import Sound.ThreadSound;
import GEO_Location.*;
import java.awt.event.*;
import java.awt.*;
import java.text.*;
import java.util.*;

public class JPanelHeap extends JPanel implements Runnable, ActionListener
{
	public static final String myClassName = "JPanelHeap";
	public static Driver driver = new Driver();
	
	JLabel jlblAvailableHeap = new JLabel("Initializing. Standby... ");
	JLabel jlblConsumedHeap = new JLabel("... ");
	JLabel jlblMaxHeap = new JLabel("... ");
	JLabel jlblTotalHeap = new JLabel("... ");
	public JLabel jlblUpTime = new JLabel("...");
	
	public static volatile String last_sensor_update = "Awaiting input...";
	JLabel jlblSocketUpdate = new JLabel("");
	
	public static JLabel jlblEncryptionKey = new JLabel("Encryption Key: //NOT SET//");
	
	long available_heap = 0;
	long max_heap = 0;
	long consumed_heap = 0;
	long total_heap = 0;
	
	public static final long start_time = System.currentTimeMillis();
	
	DecimalFormat deci_formatter = new DecimalFormat("0.00");
	
	JPanel jpnlStats = new JPanel(new GridLayout(1,5));
	JPanel jpnlOptions = new JPanel();
	
	
	
	public Timer tmr = null;
	
	public JPanelHeap()
	{
		try
		{
			//this.setLayout(new GridLayout(1,8,4,4));
			this.setLayout(new BorderLayout());
			
			jpnlStats.add(this.jlblUpTime);
			jpnlStats.add(this.jlblAvailableHeap)		;
			jpnlStats.add(this.jlblConsumedHeap)			;
			jpnlStats.add(this.jlblTotalHeap)			;
			jpnlStats.add(this.jlblMaxHeap)				;
			
			jpnlOptions.add(this.jlblEncryptionKey)		;
			
			jpnlOptions.add(this.jlblSocketUpdate)		;
			
			this.add(BorderLayout.CENTER, jpnlStats);
			this.add(BorderLayout.EAST, jpnlOptions);
			
			
			this.tmr = new Timer(1000, this);
			tmr.start();
			
		jlblSocketUpdate.setToolTipText("Specifies the Last Time an update input has been received in the system");
			
			this.validate();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
	}
		
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == this.tmr)
			{
				update_times();
			}
			
			
			
			
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae");
		}
		
		this.validate();
	}
	
	public boolean update_times()
	{
		try
		{
			this.available_heap = Runtime.getRuntime().freeMemory();
			this.max_heap = Runtime.getRuntime().maxMemory();
			this.total_heap = Runtime.getRuntime().totalMemory();
			this.consumed_heap = total_heap - available_heap;
			
			jlblMaxHeap.setText("Max Heap: " + convert_size(max_heap));
			jlblTotalHeap.setText("Total Heap: " + convert_size(total_heap));
			jlblAvailableHeap.setText("  Available Heap: " + convert_size(available_heap));
			jlblConsumedHeap.setText("Consumed Heap: " + convert_size(consumed_heap));
			jlblUpTime.setText("  Up Time: " +getTimeInterval_WithDays(System.currentTimeMillis(), start_time));
			jlblSocketUpdate.setText(last_sensor_update);
			//this.validate();
			return true;	
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_times");
		}
		
		return false;
	}
	
	public String convert_size(double size)
	{
		try
		{
			if(size / 1e12 >= 1)
				return "" + deci_formatter.format(((size + 0.0) / 1e12)) + " tb  ";
			if(size / 1e9 >= 1)
				return ("" + deci_formatter.format(((size + 0.0) / 1e9))) + " GBs  ";
			if(size / 1e6 >= 1)
				return ("" + deci_formatter.format(((size + 0.0) / 1e6))) + " MBs  ";
			if(size / 1e3 >= 1)
				return ("" + deci_formatter.format(((size + 0.0) / 1e3))) + " KBs  ";
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "convert_size");
		}
		
		return size + " bytes"; 
	}


	@Override
	public void run() {
		// TODO Auto-generated method stub
		
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
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
