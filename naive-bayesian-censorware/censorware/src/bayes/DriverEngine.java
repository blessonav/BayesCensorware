package bayes;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class DriverEngine implements Runnable {
	public String dom;
	public static boolean terminate=false;
	public static Thread thread=null;
	public void driver(String domain)
	{
		
		
		dom=domain;
		thread=new Thread(this);
		thread.start();
		
	}
	@Override
	public void run() {
		try {
			
			if(dom==null)
				return;
	/*		System.out.println("----------------------------------------------");
			System.out.println("Going to call Checkdomain on "+dom);
			System.out.println("----------------------------------------------");
		*/BayesClassifer.checkDomain(dom);
		
		for(Iterator<Site> iterator = BayesClassifer.sitesundertest.iterator(); iterator.hasNext(); ) {
			{  Site s=  iterator.next();
				if(s.url.equalsIgnoreCase(dom))
					iterator.remove();
			 }	
			}} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		}
	
	public  boolean isUnderTesting(String domain)
	{ 
	List<Site> sitesundertestlocal=BayesClassifer.sitesundertest;
		for(Iterator<Site> iterator = sitesundertestlocal.iterator(); iterator.hasNext(); ) 
		{  Site s=  iterator.next();
				if(s.url.equalsIgnoreCase(domain))
				{		return true;
				}		
			}
		return false;
		}
	
	
		


	public float HaveTested(String domain)
	{ List<Site> recentSiteslocal=BayesClassifer.recentSites;
		for(Iterator<Site> iterator = recentSiteslocal.iterator(); iterator.hasNext(); ) {
			 Site s=  iterator.next();
				if(s.url.equalsIgnoreCase(domain))
				{		return s.probability;
						
				}		
			}
			return -1.0f;
		
	}
	
	
	public static void main(String[] args){
		
		System.out.println("-------------------------------------------------------------------------");
		System.out.println("ANALYSIS AND IMPROVEMENT OF INTERNET CENSORSHIP AND SURVEILLANCE IN INDIA");
		System.out.println("GUIDE- Dr. AJEESH RAMANUJAN");
		System.out.println("DONE BY - BLESSON ANDREWS VARGHESE");
		System.out.println("-------------------------------------------------------------------------");
		
		BayesClassifer.init();
		//BayesClassifer.recentSites.clear();
	    List<Thread> threadList = getMyThreadList();        

	    

	   // System.out.println("Waiting for Child Threads to die");
	  while(!DriverEngine.terminate) {
	    for (Thread thread : threadList) {
	    	if(!thread.isAlive())
	    	{
	    		thread.start();
	    	}	
	        
	}
	  }   
	    
	}

	/**
	 * Dummy method to get a list of Threads. Content of this method may not be reviewed.
	 * Actual method do some other way to return a list of threads
	 * @return
	 */
	private static List<Thread> getMyThreadList() {
	    List<Thread> threadList = new ArrayList<>();
	    //threadList.add(new ThreadClassicPcapExample);
	   
	    PacketCaptureEngine engine = new PacketCaptureEngine();
	      Thread engineThread = new Thread(engine);
	        threadList.add(engineThread);
	    
	    return threadList;
	 }
	}
	

