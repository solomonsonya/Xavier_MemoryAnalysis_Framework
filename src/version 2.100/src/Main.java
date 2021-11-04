/**
 * 
 * @author Solomon Sonya
 *
 */

import javax.swing.SwingUtilities;

import Driver.*;
import java.io.*;

public class Main 
{

	public static void main(String[] args) 
	{
		// TODO Auto-generated method stub
		try
		{
			 SwingUtilities.invokeLater(new Runnable() {

			        @Override
			        public void run() {
			        	Start start = new Start(args);
			        	
			        	
			        }
			    });
			
			//Start start = new Start(args);
		}
		catch(Exception e)
		{
			System.out.println("Check Main...");
		}
	}

}
