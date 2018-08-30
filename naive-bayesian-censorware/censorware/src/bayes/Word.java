package bayes;

import java.io.Serializable;

public class Word implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String word;	//the word itself
	private int harmfulCount;	//number of this words appearances in spam messages
	private int harmlesCount;	//number of this words appearances in ham messages
	private float harmfulRate;	//spamCount divided by total spam count
	private float harmlesRate;	//hamCount divided by total ham count
	private float probOfHarmful;	//probability of word being spam
	
	public Word(String word){
		this.word = word;
		harmfulCount = 0;
		harmlesCount = 0;
		harmfulRate = 0.0f;
		harmlesRate = 0.0f;
		probOfHarmful = 0.0f;	
	}
	
	public Word(String word,float probOfSpam){
		this.word = word;
		this.probOfHarmful = probOfSpam;	
	}
	public int getHarmlesCount() {
		return harmlesCount;
	}public int getHarmfulCount() {
		return harmfulCount;
	}public void setWord(String word) {
		this.word = word;
	}public static long getSerialversionuid() {
		return serialVersionUID;
	}
	public void countHarmful(){
		harmfulCount++;
	}
	
	public void countHarmles(){
		harmlesCount++;
	}
	
	//calculates the probability of spam, 
	//and gives the smallest and biggest probabilities more precedence
	public void calculateProbability(int totSpam, int totHam){
		harmfulRate = harmfulCount / (float) totSpam;
		harmlesRate = harmlesCount / (float) totHam;
		
		if(harmfulRate + harmlesRate > 0){
			probOfHarmful = harmfulRate / (harmfulRate + harmlesRate);
		}
		if(probOfHarmful < 0.01f){
			probOfHarmful = 0.01f;
		}
		else if(probOfHarmful > 0.99f){
			probOfHarmful = 0.99f;
		}
	}

	
	
	
	@Override
	public boolean equals(Object obj) {
	    // TODO Auto-generated method stub
	    if(obj instanceof Word)
	    {
	    	Word temp = (Word) obj;
	        if(this.getWord()!=null && temp.getWord()!=null && (this.getWord().equalsIgnoreCase(temp.getWord())))
	            return true;
	    }
	    return false;

	}
	
	
	public String getWord() {
		return word;
	}

	public float getHarmfulRate() {
		return harmfulRate;
	}

	public float getHarmlesRate() {
		return harmlesRate;
	}

	public void setHarmlesRate(float harmlesRate) {
		this.harmlesRate = harmlesRate;
	}

	public float getProbOfHarmful() {
		return probOfHarmful;
	}

	public void setProbOfHarmful(float probOfHarmful) {
		this.probOfHarmful = probOfHarmful;
	}
	
	public void setHamCount(int hamCount) {
		this.harmlesCount = hamCount;
	}
	public void setSpamCount(int spamCount) {
		this.harmfulCount = spamCount;
	}
	public void setSpamRate(float spamRate) {
		this.harmfulRate = spamRate;
	}
}
