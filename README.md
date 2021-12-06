# Xavier_MemoryAnalysis_Framework


Xavier Framework is a user interface wrapper built on top of the Volatility(c) memory forensics framework.

## **Getting Started

The latest version of Volatility can be downloaded from https://www.volatilityfoundation.org/releases
Please download and extract the latest Volatility binary file first before running Xavier.
After Volatility is ready on your machine, run Xavier and point it to the Volatility binary (you'll be prompted).
Dump a memory image file (using a separate memory acquisition tool) to begin analysis.
You can use the Add Search Image Tab to perform keyword searches on any image file you load into Xavier.

## **Memory Acquisition

There are multiple programs useful for acquiring a memory image for analysis.
The following tools were very effective to acquire a memory image:
	DumpIt - https://www.aldeid.com/wiki/Dumpit
	Mandiant's Memoryze - https://www.fireeye.com/services/freeware/memoryze.html
	WInpmem - https://github.com/google/rekall/releases?after=v1.4.1
	Belkasoft's RAM Capture - https://belkasoft.com/ram-capturer
	Magnet RAM Capture - https://www.magnetforensics.com/free-tool-magnet-ram-capture/
	Mandiant's Redline - https://www.fireeye.com/services/freeware/redline.html
	FTK Imager - https://accessdata.com/product-download/ftk-imager-version-4.2.0

## **Memory Analysis

Once you have a memory image, you can perform analysis using Xavier (that scripts commands to Volatility)
and helps to provide additional analysis for the investigator. From Xavier, executing each plugin creates 
a separate tab to view the analysis results. An output file is also created to reference output at a later date.

## **Additional Memory Analysis Tools Include:

Volatility, Mandiant's Redline, Rekall, Autopsy, FTK Imager, OSForensics

## **Memory Image CTFs to Analyze:

Below are links to memory images/challenges/writeups I liked and would like to reference for you to use and enhance your knowledge. NOTE: These resources are maintained by others, thus, I would expect some links will die over time, if so, please contact me to update.
+ AceBear CTF 19: https://ret2.life/posts/AceBear-CTF-19/
+ AllesCTF19: https://ctftime.org/writeup/16248
+ CyberDefenders.org (Awesome site for forensics challenges and writeups!)
	++ AfricanFalls
	++ BankingTroubles
	++ CyberCorp Case 1
	++ DumpMe
	++ HireMe
	++ Injector
	++ Ulysses
+ DefCon 2019 DFIR CTF - writeup (TriageMemory) https://www.petermstewart.net/13cubed-mini-memory-ctf-write-up/#comment-7815 
+ DFIRMadness (Brilliant Forensics challenge and writeup!): https://dfirmadness.com/case-001-memory-analysis/
+ DownUnderCTF2021: https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/forensics/The_File_Is_Lava
+ Flare-on 6 2016: https://malwareunicorn.org/workshops/flareon6_2019.html#0 
+ GrrCon2015: https://malwarenailed.blogspot.com/2020/04/memory-forensics-grrcon2015-ctf.html?m=1 
+ HackTM-FindMyPass 2020: https://ptr-yudai.hatenablog.com/entry/2020/02/06/130551#forensics-474pts-Find-my-pass
+ Houseplant CTF 2020 - Imagery: https://ctftime.org/writeup/20330
+ InCTF Internationals 2020 
	++ Investigation: https://stuxnet999.github.io/inctfi/2020/08/06/Investigation-InCTFi2020.html
	++ Investigation Continues: https://stuxnet999.github.io/inctfi/2020/08/06/InvestigationContd-InCTFi20.html
	++ LOGarithm: https://stuxnet999.github.io/inctfi/2020/08/05/InCTFi-LOGarithm.html
+ Magnet Forensics (They have awesome challenges as well!!!)
	++ CTF 2020: https://svch0st.medium.com/magnet-virtual-summit-2020-ctf-memory-7927c755a182
+ MemLabs: https://github.com/stuxnet999/MemLabs (check out the labs, search for writeups - these are pretty cool challenges!)
+ OtterCTF2018: https://www.petermstewart.net/otterctf-2018-memory-forensics-write-up/
+ SamsClass: https://samsclass.info/121/proj/p5-Vol.htm 
+ Securinets CTF Quals 2019 - Rare to Win: https://ctftime.org/writeup/14438




## **Disclaimer:

This is the initial beta release of Xavier.
So far, I've only developed and tested this version of Xavier on a Windows OS machines...
I'll come back later and ensure it is compatible on *nix versions.

## **Questions/Updates?

If you have any questions or update suggestions, please feel free to contact me.

Cheers!

-Solomon Sonya Twitter: @Carpenter1010
