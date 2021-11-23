/**
 * @author Solomon Sonya
 */


package Interface;

import java.awt.*;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;
import javax.swing.text.StyledDocument;

public class JTextPane_Solomon extends JPanel
{
	public static String myClassName = "JTextPane_Solomon";
	
	public volatile StyleContext context = new StyleContext();
	public volatile StyledDocument document = new DefaultStyledDocument(context);
	public volatile Style style = context.getStyle(StyleContext.DEFAULT_STYLE);
	public volatile JScrollPane jscrlpne = null;
	public volatile JTextPane jtxtpne = null;
	
    
    /**
     * Enable word wrapping by limiting the max height and width. Otherwise, set those to -1
     * 
     * Example: 		JTextPane_Solomon jtxtpne = new JTextPane_Solomon(true, driver.fnt_20, true, 10,10, false); 
     * 	public volatile static Font fnt_20 = new Font("Dialog", Font.BOLD, 20);
     * @param word_wrap
     * @param fnt
     * @param center_align_text
     * @param max_width_if_applicable
     * @param max_height_if_applicable
     * @param editable
     */
	public JTextPane_Solomon(Font fnt, Color foreground, boolean center_align_text, int max_width_if_applicable, int max_height_if_applicable, boolean editable)
	{
		if(center_align_text) 
			StyleConstants.setAlignment(style, StyleConstants.ALIGN_CENTER);    
		 
		 jtxtpne = new JTextPane(document);
		 //textPane.setText();		
		 jtxtpne.setOpaque(false);
		 
		 jscrlpne = new JScrollPane(jtxtpne);
		 
		 this.jtxtpne.setEditable(editable);
		 
		 this.setLayout(new BorderLayout());
		 this.add(BorderLayout.CENTER, jscrlpne);
		 
		 try	{	jscrlpne.setBorder(null);	}	catch(Exception e){}
		 
		 if(fnt != null)
			 jtxtpne.setFont(fnt);
		 
		 if(foreground != null)
			 try	{	this.jtxtpne.setForeground(foreground);	}	catch(Exception e)	{	this.jtxtpne.setForeground(Color.black);	}	
		 
		 if(max_width_if_applicable > 0 && max_height_if_applicable > 0)
		 {
			 try
			 {
				 jscrlpne.setPreferredSize(new Dimension(max_width_if_applicable,max_height_if_applicable));
			 }
			 catch(Exception e)
			 {
				 
			 }
		 }
	}
	
	public boolean append(String text)
	{
		try
		{
			document.insertString(document.getLength(), text, style);
			return true;
		}
		catch(Exception e)
		{
			System.out.println("Exception handled in " + myClassName + " mtd: append");
		}
		
		return false;
	}
	
	public boolean setText(String text)
	{
		try
		{
			try	{	document.remove(0, document.getLength());	}	catch(Exception e)	{	jtxtpne.setText("");	}
			document.insertString(0, text, style);
			return true;
		}
		catch(Exception e)
		{
			System.out.println("Exception handled in " + myClassName + " mtd: setText");
		}
		
		return false;
	}
}
