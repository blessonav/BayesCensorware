package jnetpcapDemo;



public class Test {
	
  static {
    try {
    	System.load("/usr/lib/jnetpcap");
    	//System.load("/usr/lib/libopen-pal.so.13.0.2");
    } catch (UnsatisfiedLinkError e) {
      System.err.println("Native code library failed to load.\n" + e);
      System.exit(1);
    }
  }

  public static void main(String argv[]) 
  {
    
    System.out.println("Loaded");    
  }
}