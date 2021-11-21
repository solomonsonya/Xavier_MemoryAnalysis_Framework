# Xavier_MemoryAnalysis_Framework 


Xavier Framework is a user interface wrapper built on top of the Volatility(c) memory forensics framework.

Getting Started
=====================================================
The latest version of Volatility can be downloaded from https://www.volatilityfoundation.org/releases
Please download and extract the latest Volatility binary file first before running Xavier.
After Volatility is ready on your machine, run Xavier and point it to the Volatility binary (you'll be prompted).
Dump a memory image file (using a separate memory acquisition tool) to begin analysis.
You can use the Add Search Image Tab to perform keyword searches on any image file you load into Xavier.

Memory Acquisition
=====================================================
There are multiple programs useful for acquiring a memory image for analysis.
The following tools were very effective to acquire a memory image:
	DumpIt - https://www.aldeid.com/wiki/Dumpit
	Mandiant's Memoryze - https://www.fireeye.com/services/freeware/memoryze.html
	WInpmem - https://github.com/google/rekall/releases?after=v1.4.1
	Belkasoft's RAM Capture - https://belkasoft.com/ram-capturer
	Magnet RAM Capture - https://www.magnetforensics.com/free-tool-magnet-ram-capture/
	Mandiant's Redline - https://www.fireeye.com/services/freeware/redline.html
	FTK Imager - https://accessdata.com/product-download/ftk-imager-version-4.2.0

Memory Analysis
=====================================================
Once you have a memory image, you can perform analysis using Xavier (that scripts commands to Volatility)
and helps to provide additional analysis for the investigator. From Xavier, executing each plugin creates 
a separate tab to view the analysis results. An output file is also created to reference output at a later date.

Additional Memory Analysis Tools Include:
=====================================================
Volatility, Mandiant's Redline, Rekall, Autopsy, FTK Imager, OSForensics

Disclaimer:
=====================================================
This is the initial beta release of Xavier.
So far, I've only developed and tested this version of Xavier on a Windows OS machines...
I'll come back later and ensure it is compatible on *nix versions.

Questions/Updates?
=====================================================
If you have any questions or update suggestions, please feel free to contact me.

Cheers!

-Solomon Sonya @Carpenter1010
