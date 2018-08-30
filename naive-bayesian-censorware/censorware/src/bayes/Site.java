package bayes;

import java.io.Serializable;
import java.util.Date;

public class Site  implements Serializable
{
	public String url;
	public Date accessDate;
	public float probability;
	
	public Site(String url,Date accessDate,float probability) {
		this.url=url;
		this.accessDate=accessDate;
		this.probability=probability;
	}
}
