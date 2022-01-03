/**
 * @author Solomon Sonya
 */

package Interface;

import javax.swing.*;
import javax.swing.Timer;
import javax.swing.border.BevelBorder;
import Driver.*;
import java.awt.event.*;
import java.awt.*;
import java.text.*;
import java.util.*;

public class JPanelTime extends JPanel implements Runnable, ActionListener
{
	public static final String myClassName = "JPanelTime";
	public static Driver driver = new Driver();
	
	
	
	public volatile JPanel jpnlTimes = new JPanel(new GridLayout(1,8, 4,4));
	public volatile JLabel jlblMyTimeZone = new JLabel("Initializing. Standby...", JLabel.CENTER);
	public volatile JLabel jlblPacific = new JLabel("Pacific", JLabel.CENTER);
	public volatile JLabel jlblMountain = new JLabel("Mountain", JLabel.CENTER);
	public volatile JLabel jlblCentral = new JLabel("Central", JLabel.CENTER);
	public volatile JLabel jlblEastern = new JLabel("Eastern", JLabel.CENTER);
	public volatile JLabel jlblZulu = new JLabel("Zulu", JLabel.CENTER);
	
	JPanel jpnlMyTime = new JPanel();
	JPanel jpnlPacific = new JPanel();
	JPanel jpnlMountain = new JPanel();
	JPanel jpnlCentral = new JPanel();
	JPanel jpnlEastern = new JPanel();
	JPanel jpnlZulu = new JPanel();
	
	Date date = new Date();
	SimpleDateFormat dateFormat = new SimpleDateFormat("EE - dd MMM yyyy - HH:mm \"ss - zzzz");
	
	SimpleDateFormat dateFormat_Pacific = new SimpleDateFormat("HH:mm \"ss");
	SimpleDateFormat dateFormat_Mountain = new SimpleDateFormat("HH:mm \"ss");
	SimpleDateFormat dateFormat_Central = new SimpleDateFormat("HH:mm \"ss");
	SimpleDateFormat dateFormat_Eastern = new SimpleDateFormat("HH:mm \"ss");
	SimpleDateFormat dateFormat_Zulu = new SimpleDateFormat("HH:mm \"ss");
	
	Font fnt1 = new Font("Dialog", Font.PLAIN, 12);
	
	public Timer tmr = null;
	
	public JPanelTime()
	{
		try
		{
			this.setLayout(new BorderLayout());
			this.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
			
			
			jpnlMyTime.add(jlblMyTimeZone);
			
			
			jpnlPacific.add(this.jlblPacific);
			jpnlMountain.add(this.jlblMountain);
			jpnlCentral.add(this.jlblCentral);
			jpnlEastern.add(this.jlblEastern);
			jpnlZulu.add(this.jlblZulu);
			
			
			jpnlTimes.add(this.jpnlPacific);
			jpnlTimes.add(this.jpnlMountain);
			jpnlTimes.add(this.jpnlCentral);
			jpnlTimes.add(this.jpnlEastern);
			jpnlTimes.add(this.jpnlZulu);
			
			this.add(BorderLayout.WEST, jpnlMyTime);
			
			
			this.add(BorderLayout.CENTER, jpnlTimes);
			
			/*jpnlMyTime.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
			jpnlPacific.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
			jpnlMountain.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
			jpnlCentral.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
			jpnlEastern.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
			jpnlZulu.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));*/
			
			dateFormat_Pacific.setTimeZone(TimeZone.getTimeZone("America/Los_Angeles"));
			dateFormat_Mountain.setTimeZone(TimeZone.getTimeZone("America/Denver"));
			dateFormat_Central.setTimeZone(TimeZone.getTimeZone("America/Chicago"));
			dateFormat_Eastern.setTimeZone(TimeZone.getTimeZone("America/New_York"));
			dateFormat_Zulu.setTimeZone(TimeZone.getTimeZone("Zulu"));
			
			jlblMyTimeZone.setFont(fnt1);
			jlblCentral.setFont(fnt1);
			jlblPacific.setFont(fnt1);
			jlblMountain.setFont(fnt1);			
			jlblEastern.setFont(fnt1);
			jlblZulu.setFont(fnt1);
			
			jlblMyTimeZone.setForeground(Color.blue.darker().darker());
			
			this.tmr = new Timer(1000, this);
			tmr.start();
			
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
				update_times();
			
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
			date.setTime(System.currentTimeMillis());
			
			jlblMyTimeZone.setText("  " + dateFormat.format(date));
			this.jlblPacific.setText("" + dateFormat_Pacific.format(date) + " - Pacific");
			this.jlblMountain.setText("" + dateFormat_Mountain.format(date) + " - Mountain");
			this.jlblCentral.setText("" + dateFormat_Central.format(date) + " - Central");
			this.jlblEastern.setText("" + dateFormat_Eastern.format(date) + " - Eastern");
			this.jlblZulu.setText("" + dateFormat_Zulu.format(date) + " - Zulu");
			
			return true;	
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_times");
		}
		
		return false;
	}


	@Override
	public void run() {
		// TODO Auto-generated method stub
		
	}

}
