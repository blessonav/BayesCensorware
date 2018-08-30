import java.io.*;
import java.util.*;
public class TrainingNormal{
	public static void main(String args[]){
		File loc = new File("/home/hduser/extra/nonspam-train/");
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
			int vocabSize = 264821;
			double num=0;
			double p=0;
		        double den=1;
			int spamSize = hm.size();
			//libc.chmod("/home/hduser/data/out/dict.txt", 0755)
			PrintWriter writer = new PrintWriter("./out/nonspamVector");
			for(Map.Entry<String,Integer>e:hm.entrySet()){
				num = e.getValue()+1;
				//System.out.println(e.getKey()+" "+e.getValue());	
				den = spamSize+vocabSize;
				double ratio = num/den;
				p=Math.log(ratio);
				//System.out.println(ratio + " "+ num + " "+ den +  "  " +p);
                        	writer.write(e.getKey()+" " + p);
				writer.println();
                        }
                	writer.close();
		}
		catch(Exception e){
			e.printStackTrace(System.out);
		}

	}
}
