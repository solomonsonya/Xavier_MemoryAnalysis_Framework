/**
 * @author Solomon Sonya
 */


package Driver;

public class Tuple 
{
	public static final String myClassName = "Tuple";
	
	public volatile String name = "";
	public volatile int value = 0;
	
	public volatile String value_1 = "";
	public volatile String value_2 = "";
	
	public Tuple(String Name, int val)
	{
		try
		{
			name = Name;
			value = val;
		}
		catch(Exception e)
		{
			
		}
		
	}
	
	public Tuple(String val1, String val2)
	{
		try
		{
			value_1 = val1; 
			value_2 = val2;
		}
		catch(Exception e)
		{
						
		}
	}
	
	public boolean increment()
	{
		try
		{
			++value;
		}
		catch(Exception e)
		{
						
		}
		
		return true;
	}
}
