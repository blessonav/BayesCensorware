package bayes;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.WriteAbortedException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;

public class BayesClassifer implements Runnable {
	static List<Word> words = new ArrayList<Word>();
	public static List<Site> recentSites=new ArrayList<Site>();
	public static List<Site> sitesundertest=new ArrayList<Site>();
	BufferedWriter out;
	private volatile boolean running = true, insideinit = true;
	public static Thread thread = null;

	BayesClassifer() {
	}

	BayesClassifer(int random) {
		thread = new Thread(this);
		thread.start();
	}

	@Override
	public void run() {

		while (true) {
			if (words != null && !words.isEmpty()) {
				List<Word> wordslocal = words;

				File file = new File("blocked");
				while (file.exists())
					file.delete();

				try {
					file.createNewFile();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				try {
					FileOutputStream f;
					f = new FileOutputStream(file);
					ObjectOutputStream s;
					s = new ObjectOutputStream(f);
					for (Word key : wordslocal) {
						if(key!=null) {
							s.writeObject(key);
					}}

					s.close();
					Thread.sleep(10000);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		
		

			if (recentSites != null && !recentSites.isEmpty()) {
				List<Site> recentSiteslocal = recentSites;

				File file = new File("recentsites");
				while (file.exists())
					file.delete();

				try {
					file.createNewFile();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				try {
					FileOutputStream f;
					f = new FileOutputStream(file);
					ObjectOutputStream s;
					s = new ObjectOutputStream(f);
					for (Site key : recentSiteslocal) {
						if(key!=null) {
						long diff = new Date().getTime() - key.accessDate.getTime();
						long days=TimeUnit.DAYS.convert(diff, TimeUnit.MILLISECONDS);
						if(days>=2)
						{	
							recentSiteslocal.remove(key);
							recentSites.remove(key);
							
						}
						else {
							s.writeObject(key);
						}
						}}

					s.close();
					Thread.sleep(10000);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		
		
		
		}
	}

	public static void poplulatewordsfromblocked() throws IOException {
		FileInputStream fis;
		try {
			fis = new FileInputStream("blocked");

			ObjectInputStream ois = new ObjectInputStream(fis);
			while (true) {
				Word result = null;
				try {
					result = (Word) ois.readObject();
				} catch (EOFException exc) {
					break;
				}
				if (result != null)
				{
					
					if (!containsWord(words,result.getWord())) {
								words.add( result);
				}}
			}
			ois.close();
			
			
			
			
				fis = new FileInputStream("recentsites");

				try{
					ois = new ObjectInputStream(fis);
				}
				catch(Exception ex)
				{
					return;
				}
				while (true) {
					Site result = null;
					try {
						result = (Site) ois.readObject();
					} catch (EOFException exc) {
						break;
					}
					if (result != null)
					{
						long diff = new Date().getTime() - result.accessDate.getTime();
						long days=TimeUnit.DAYS.convert(diff, TimeUnit.MILLISECONDS);
						if(days<2)
						{
							
							
							
							
							String ur=result.url;
							recentSites.removeIf(obj -> obj.url.equalsIgnoreCase(ur));
							recentSites.add( result);
						
						
						}
					}
					
				}
				ois.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			if (e instanceof WriteAbortedException) {
				throw e;

			}
			if (e instanceof EOFException) {
				throw e;

			}
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public static void main(String[] args) {
		try {
		//	blockSite("http://www.agame.com/ ");
			unblockSite("http://www.agame.com/ ");
			/*Bayes run = new Bayes();
			if (words.isEmpty()) {
				File file = new File("blocked");
				if (!file.exists())
					run.initialtraining();
				else {
					try {
						poplulatewordsfromblocked();
					} catch (IOException e) {
						words.clear();
						run.initialtraining();
					}
				}
				Bayes bay = new Bayes(43);

				// new Thread(this).start();
			}
			while (words == null || words.isEmpty())
				;
			String strdomain = "https://movieweb.com/";
			checkDomain(strdomain);*/
		} catch (Exception e) {
			System.out.println("AN ERROR HAS OCCURED");
		}
	}
public static void init()
{
	try {
		BayesClassifer run = new BayesClassifer();
		// Running initial training as words is empty
		File file = new File("blocked");
		if (!file.exists())
			run.initialtraining();
		else {
			try {
				poplulatewordsfromblocked();
			} catch (IOException e) {
				words.clear();
				run.initialtraining();
			}
		}
		if (BayesClassifer.thread == null || !BayesClassifer.thread.isAlive())
			run = new BayesClassifer(43);
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}

}
	public static void checkDomain(String strdomain) {
		String url=strdomain;
		System.out.println("-------------------------------------------------------------------------");
		System.out.println("Checking whether domain : " + strdomain + " , is HARMFUL");
		System.out.println("-------------------------------------------------------------------------");
		BayesClassifer run = new BayesClassifer();
		/*if (words == null || words.isEmpty()) {

			}*/
		if (containsWord(words , strdomain.replaceAll("\\W", "").toLowerCase())) {
			{
				Word w = (Word) getWord(words,strdomain.replaceAll("\\W", "").toLowerCase());
				if (w.getProbOfHarmful() >= 0.9f)
					return;
			}
		}

		// run.filter(args[1]);
		System.out.println("-------------------------------------------------------------------------");
		System.out.println("Trying to read content of wepage : " + strdomain);
		System.out.println("-------------------------------------------------------------------------");
		String pageContent = "";
		try {
			pageContent = Webscraper.getWebContent(strdomain);
		} catch (Exception ex) {
			if (ex instanceof FailingHttpStatusCodeException) {
				if (ex.getMessage().contains("Forbidden")) {
					System.out.println("Reading content on page :" + strdomain + "  is forbidden. Therefore marking as harmful");
					recentSites.add(new Site(strdomain,new Date(),1));
					Word w = new Word(strdomain);
					w.setProbOfHarmful(1f);
					words.add(w);
					
				}
			} else
				{System.out.println("The webpage " + strdomain + " Cannot be read. Therefore Marking as harmful");
				recentSites.add(new Site(strdomain,new Date(),1));
				Word w = new Word(strdomain);
				w.setProbOfHarmful(1f);
				words.add(w);
				}
			return;}

		float totalProbability = run.calculateBayesPage(pageContent);
		//totalProbability=1.0f;
		recentSites.add(new Site(strdomain,new Date(),totalProbability));
		if (totalProbability > 0.9f) {

			strdomain = strdomain.replaceAll("\\W", "");
			strdomain = strdomain.toLowerCase();
			// toDelete = new Set(['abc', 'efg']);
			// newArray = arrayOfObjects.filter(obj => !toDelete.has(obj.id));
			Word w = new Word(strdomain);
			w.setHarmlesRate(0);
			w.setSpamRate(1);
			w.setSpamCount(1);
			w.setHamCount(0);
			w.setProbOfHarmful(totalProbability);
			words.add(w);
			blockSite(url);
			System.out.println("-------------------------------------------------------------------------");
			System.out.println("The webpage " + strdomain + " is harmful and is blocked from further access");
			System.out.println("-------------------------------------------------------------------------");

		} else {
			System.out.println("-------------------------------------------------------------------------");
			System.out.println("The webpage " + strdomain + " is not harmful and can be accessed from now on");
			System.out.println("-------------------------------------------------------------------------");
			unblockSite(url);
			strdomain = strdomain.replaceAll("\\W", "");
			strdomain = strdomain.toLowerCase();
			// toDelete = new Set(['abc', 'efg']);
			// newArray = arrayOfObjects.filter(obj => !toDelete.has(obj.id));
			words= removeWord(words,strdomain);
		}

	}

	// uses a train-file to make a hashmap containing all words, and their
	// probability of being spam
	public void initialtraining() throws IOException {
		String input = "train.txt";
		int totalSpamCount = 0;
		int totalHamCount = 0;
		BufferedReader in = new BufferedReader(new FileReader(input));
		String line = in.readLine();
		while (line != null) {
			if (!line.equals("")) {
				String type = line.split("\t")[0];
				String sms = line.split("\t")[1];
				for (String word : sms.split(" ")) {
					word = word.replaceAll("\\W", "");
					word = word.toLowerCase();
					Word w = null;
					if (containsWord(words,word)) {
						w = (Word) getWord(words, word);
					} else {
						w = new Word(word);
						words.add(w);
					}
					if (type.equals("ham")) {
						w.countHarmles();
						totalHamCount++;
					} else if (type.equals("spam")) {
						w.countHarmful();
						totalSpamCount++;
					}
				}
			}
			line = in.readLine();
		}
		in.close();

		for (Word key : words) {
			key.calculateProbability(totalSpamCount, totalHamCount);
		}
		insideinit = false;
	}


	// make an arraylist of all words in an sms, set probability of spam to 0.4 if
	// word is not known
	public ArrayList<Word> makeWordList(String sms) {
		ArrayList<Word> wordList = new ArrayList<Word>();
		for (String word : sms.split(" ")) {
			word = word.replaceAll("\\W", "");
			word = word.toLowerCase();
			Word W = null;
			if (containsWord(words,word)) {
				W = (Word) getWord(words,word);
			} else {
				W = new Word(word);
				W.setProbOfHarmful(0.40f);
			}
			wordList.add(W);
		}
		return wordList;
	}

	// Applying Bayes rule and calculating probability of ham or spam. Return true
	// if spam, false if ham
	public float calculateBayesPage(String PageContent) {
		int noOfSentences = 0;
		float probOfSpam = 0, totalProbability = 0;
		for (String line : PageContent.split("\n")) {
			if (!line.equals("")) {
				noOfSentences++;
				ArrayList<Word> sms = makeWordList(line);
				float probabilityOfPositiveProduct = 1.0f;
				float probabilityOfNegativeProduct = 1.0f;
				for (int i = 0; i < sms.size(); i++) {
					Word word = (Word) sms.get(i);
					probabilityOfPositiveProduct *= word.getProbOfHarmful();
					probabilityOfNegativeProduct *= (1.0f - word.getProbOfHarmful());
				}
				probOfSpam = probabilityOfPositiveProduct
						/ (probabilityOfPositiveProduct + probabilityOfNegativeProduct);
			}
			totalProbability = totalProbability + probOfSpam;
		}
		totalProbability /= noOfSentences;
		return totalProbability;
	}
	
	
	public static boolean containsWord( List<Word> list, String name){
		for(Word o : list) {
	        if(o != null && o.getWord().equalsIgnoreCase(name)) {
	            return true;
	        }
	    }
	    return false;

}
	public static Word getWord( List<Word> list, String name){
		for(Word o : list) {
	        if(o != null && o.getWord().equalsIgnoreCase(name)) {
	            return o;
	        }
	    }
	    return null;

}
	
	
	
public static List<Word> removeWord( List<Word> list, String name){
		
		list.removeIf(s-> s.getWord().equalsIgnoreCase(name));
		/*for(Word o : list) {
	        if(o != null && o.getWord().equalsIgnoreCase(name)) {
	        	list.remove(o);
	        	
	        }*/
	    
	    return list;

}
	
	/*public List<Word> removeDuplicateWords(List<Word> metrics) {

	    List<Word> copy = new ArrayList<Word>();
	    Collections.sort(copy, new SortComparator());

	    Set<Word> set = new TreeSet<Word>(new Comparator<Word>() {

	        @Override
	        public int compare(Word o1, Word o2) {
	            int result = 0;
	            // compare the two metrics given your rules
	            return result;
	        }
	    });

	    for(Word word : copy) {
	        set.add(word);
	    }

	    List<Word> result = Arrays.asList(set.toArray());
	    return result;
	 }

	class SortComparator implements Comparator<Word> {

	    @Override
	    public int compare(Word o1, Word o2) {
	        int result = 0;
	        if(o2.getWord() != null && o1.getWord()!= null) {
	            result = o2.getWord() .compareTo(o1.getWord() );
	        }
	        return result;
	    }

	}*/
	
	public static void blockSite(String url) {
	    // Note that this code only works in Java 7+,
	    // refer to the above link about appending files for more info

	    // Get OS name
	    String OS = System.getProperty("os.name").toLowerCase();

	    // Use OS name to find correct location of hosts file
	    String hostsFile = "";
	    if ((OS.indexOf("win") >= 0)) {
	        // Doesn't work before Windows 2000
	        hostsFile = "C:\\Windows\\System32\\drivers\\etc\\hosts";
	    } else if ((OS.indexOf("mac") >= 0)) {
	        // Doesn't work before OS X 10.2
	        hostsFile = "etc/hosts";
	    } else if ((OS.indexOf("nux") >= 0)) {
	        hostsFile = "/etc/hosts";
	    } else {
	        // Handle error when platform is not Windows, Mac, or Linux
	        System.err.println("Sorry, but your OS doesn't support blocking.");
	        System.exit(0);
	    }

	    // Actually block site
	    try {
			Files.write(Paths.get(hostsFile),
			            ("\n127.0.0.1 " + url).getBytes(),
			            StandardOpenOption.APPEND, StandardOpenOption.CREATE);
			while(url.endsWith("\\") ||url.endsWith("/")||url.endsWith(" "))
					url=url.substring(0,url.length()-1);
			Files.write(Paths.get(hostsFile),
		            ("\n127.0.0.1 " + url).getBytes(),
		            StandardOpenOption.APPEND, StandardOpenOption.CREATE);
			Files.write(Paths.get(hostsFile),
		            ("\n127.0.0.1 " + url.substring(url.indexOf("//")+2)).getBytes(),
		            StandardOpenOption.APPEND, StandardOpenOption.CREATE);
		} catch (IOException e) {
			System.err.println("Sorry, but your OS doesn't support blocking.");
			e.printStackTrace();
		}
	}
	
	
	public static void unblockSite(String url)
    {
        try
        {
        	String OS = System.getProperty("os.name").toLowerCase();
        	url=url.substring(url.indexOf("www.")+3);
        	while(url.endsWith("\\") ||url.endsWith("/")||url.endsWith(" "))
				url=url.substring(0,url.length()-1);
        	String hostsFile = "";
    	    if ((OS.indexOf("win") >= 0)) {
    	        // Doesn't work before Windows 2000
    	        hostsFile = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    	    } else if ((OS.indexOf("mac") >= 0)) {
    	        // Doesn't work before OS X 10.2
    	        hostsFile = "etc/hosts";
    	    } else if ((OS.indexOf("nux") >= 0)) {
    	        hostsFile = "/etc/hosts";
    	    } else {
    	        // Handle error when platform is not Windows, Mac, or Linux
    	        System.err.println("Sorry, but your OS doesn't support blocking.");
    	        System.exit(0);
    	    }

    	    // Actually block site
    	   
                BufferedReader file = new BufferedReader(new FileReader(hostsFile));
                String line;
                String input = "";
                while ((line = file.readLine()) != null) 
                {
                    //System.out.println(line);
                    if (!line.contains(url))
                    {
                        input += line + '\n';
                    }   
                }
                FileOutputStream File = new FileOutputStream(hostsFile);
                File.write(input.getBytes());
                file.close();
                File.close();
        }
        catch (Exception e)
        {
                System.out.println("Problem reading file.");
        }
    	   
    }
    }
	
	


