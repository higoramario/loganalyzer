package br.usp.each.saeg.loganalyzer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.generationjava.io.CsvWriter;


public class LogWriter {
	
	private Map<String,List<String>> results;
	String PATHFILE = "/home/higor/Dropbox/user-study/process-logs/quest.csv";
	
	public LogWriter(Map<String,List<String>> mapResults){
		results = new HashMap<String,List<String>>();
		results.putAll(mapResults);
	}
	
	private void fillOutQuestionnaire(CsvWriter csv) throws IOException {
		int questionnaireSize = 0;
		Set<String> logs;
		if(results != null){
			logs = results.keySet();
			for(String file:logs){
				questionnaireSize = results.get(file).size();
				break;
			}
		
			for(int i = 0; i < questionnaireSize; i++){
				for(String file : logs){
					List<String> fileList = results.get(file);
					csv.writeField(fileList.get(i));
				}
				csv.endBlock();
			}
		}
		
		
	}
	
	public byte[] export() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		CsvWriter csv = new CsvWriter(new OutputStreamWriter(baos));
		csv.setFieldDelimiter(';');
		csv.setBlockDelimiter('\n');
		
		fillOutQuestionnaire(csv);
		
		csv.close();
		return baos.toByteArray();
	}

	
	public void generateCSVFile(){
		try {
 			OutputStream os = new FileOutputStream(new File(PATHFILE));
            os.write(export());
            os.close();
	 	} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
