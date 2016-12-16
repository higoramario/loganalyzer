package br.usp.each.saeg.loganalyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class LogReader {
	
	public File[] loadLogFiles(String path){
		File logFiles[] = null;
		File logDir = new File(path);
		if(logDir.isDirectory()){
			logFiles = logDir.listFiles();
		}
		return logFiles;
	}
	
	
	public List<String> readLog(File file){
		List<String> logContent = new ArrayList<String>();
		BufferedReader reader;
		String logLine = "";
		try {
			reader = new BufferedReader(new FileReader(file));
			while((logLine = reader.readLine()) != null){
				logContent.add(logLine);
				System.out.println(logLine);
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return logContent;
	}



}
