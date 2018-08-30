import java.io.*;
import java.util.*;
public class NaiveBayes{
	public static void main(String args[]){
		File loc = new File("/home/hduser/extra/spam-train/");
		getWordCount(loc);
	}
	public static void getWordCount(File folder){
		int count=0;
		HashMap<String,Integer> hm = new HashMap<String,Integer>();
		//PrintWriter writer = new PrintWriter("/home/hduser/data/out/dict.txt");
	 	File[] listofFiles = folder.listFiles();
		for(File f:listofFiles){
			if(f.isFile()){
				//System.out.println(f.getName());
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
			//libc.chmod("/home/hduser/data/out/dict.txt", 0755);
			PrintWriter writer = new PrintWriter("./out/dict.txt");
			for(Map.Entry<String,Integer>e:hm.entrySet()){
                        	writer.write(e.getKey()+" " + e.getValue());
				writer.println();
                        }
                	writer.close();
		}
		catch(Exception e){
			e.printStackTrace(System.out);
		}

	}
}
