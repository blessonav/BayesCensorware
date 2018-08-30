import java.io.*;
import java.util.*;
public class Classify{
	public static void main(String args[]){
		File loc = new File("/home/hduser/extra/spam-test/");
		getWordCount(loc);
	}
	public static void getWordCount(File folder){
		int spam=0;
		HashMap<String,Integer> hm = new HashMap<String,Integer>();
		//PrintWriter writer = new PrintWriter("/home/hduser/data/out/spamVector");
	 	File[] listofFiles = folder.listFiles();
		for(File f:listofFiles){
			if(f.isFile()){
				System.out.println(spam + " "+ f.getName());
				spam++;
				try{
					Scanner s = new Scanner(f).useDelimiter("[^a-zA-Z]");
					while(s.hasNext()){
						String word = s.next().toLowerCase();
						if(hm.containsKey(word)){
							hm.put(word,hm.get(word)+1);
						}
						else{
							hm.put(word,1);
						}
				
					}
					
				}
				catch(Exception e){
					//System.out.println(e.stackTrace());	
					e.printStackTrace(System.out);
				}
			}
		
		}
		 try{
		     double spamd=0;
		     double nonspamd=0;
		     HashMap<String,Double>sp = new HashMap<String,Double>();
		     BufferedReader br = new BufferedReader(new FileReader("./out/spamVector"));
		     String line="";
	             //line = br.readLine();	
		     while((line = br.readLine())!=null){
		     	String parts[] = line.split(" ");
			double v =  Double.parseDouble(parts[1]);
			sp.put(parts[0],v);
			//System.out.println("spam "+ parts[0]);
		     }
		     HashMap<String,Double>nsp = new HashMap<String,Double>();
		     BufferedReader br1 = new BufferedReader(new FileReader("./out/nonspamVector"));
		     String line1 = "";	
		     while((line = br.readLine())!=null){
		     	String parts[] = line.split(" ");
			double v = Double.parseDouble(parts[1]);
			nsp.put(parts[0],v);
			//System.out.println("non" + " " + parts[0]);
		     }
	             for(Map.Entry<String,Integer> e: hm.entrySet()){
		     	String word = e.getKey();
			if(sp.containsKey(word)) {
				spamd = spamd + sp.get(word);
				//System.out.println(word + " "+ spamd);
			}

			if(nsp.containsKey(word)) {
				nonspamd = nonspamd + nsp.get(word);  
				//System.out.println(word + " "+nonspamd);
			}
		
		     }
		     double totalspam = spamd + Math.log(0.5);
		     double totalnon = nonspamd + Math.log(0.5);		
		     if(totalspam > totalnon)System.out.println("Spam");
		     else System.out.println("NonSpam");		 				
		}
		catch(Exception e){
			e.printStackTrace(System.out);
		}
		
	}
}
