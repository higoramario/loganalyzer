package br.usp.each.saeg.loganalyzer;

import java.io.File;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class LogAnalyzer {

	private final String LOGPATH = "/home/higor/data/user-study/logs/";
	private LogReader reader;
	private File logList[];
	private List<String> logContent;
	private Map<File,List<String>> results;
	private List<String> questions;
	private SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
	
	private final String IDNUMBER = "ID number is ";
	private final String IS_JSOUP = "[jsoup]";
	private final String IS_XSTREAM = "[xstream]";
	private final String IS_JTOPAS = "[jtopas-0.4]";
	private final String IS_LINE = "[Line]";
	private final String IS_METHOD = "[Roadmap]";
	private final String IS_JAGUAR = "[TableViewer]";
	private final String IS_JAGUAR_1ST = "[StartJaguarAction] " + IDNUMBER;
	private final String ISNOT_JAGUAR_1ST = "[RunManualDebuggingHandler]";
	private final String START_JAGUAR = "[StartJaguarAction] jaguar debugging session started";
	private final String STOP_JAGUAR = "[StopJaguarAction] jaguar debugging session stopped";
	private final String START_ECLIPSE = "[StartEclipseAction] eclipse debugging session started";
	private final String STOP_ECLIPSE = "[StopEclipseAction] eclipse debugging session stopped";
	private final String BEFORE_METHOD_NAME = "[name=";
	private final String BEFORE_LINE_NUMBER = "[line=";
	
	private final String CLICK_ON_JAGUAR_METHOD = "[TableViewer] [Roadmap] click";
	private final String CLICK_ON_JAGUAR_LINE = "[TableViewer] [Line] click";
	private final String CLICK_ON_JAGUAR_TEXT = "[Text] change";
	private final String CLICK_ON_JAGUAR_SLIDER = "[Slider] changed";
	
	private final String EDITOR_CARET = "[EditorTracker] caret";
	private final String EDITOR = "[EditorTracker]";
	private final String CLICK_ON_EDITOR = "click @ line";
	private final String EDITOR_MOUSE_HOUVER = "[mouse hover] @ line";
	private final String METHOD_MOUSE_HOVER = "[RoadmapLabelProvider] [Mouse hover]";
	private final String LINE_MOUSE_HOVER = "[RequirementLabelProvider] [Mouse hover]";
	
	private final String METHOD_NAME_BEGIN_INDEX = ".";
	private final String METHOD_NAME_END_INDEX = ")";
	private final String LINE_NAME_BEGIN_INDEX = "content= \"";
	private final String LINE_NAME_END_INDEX = "\"]";
	
	private final String JSOUP = "jsoup";
	private final String XSTREAM = "xstream";
	private final String LINE = "line";
	private final String METHOD = "method";
	private final String YES = "yes";
	private final String NO = "no";
	
	private int numberOfJaguarStarts = 0;
	private int numberOfJaguarStops = 0;
	private int numberOfEclipseStarts = 0;
	private int numberOfEclipseStops = 0;
	
	private long jaguarStartTime;
	private long jaguarStopTime;
	private long eclipseStartTime;
	private long eclipseStopTime;
	
	
	
	public LogAnalyzer(){
		reader = new LogReader();
		logList = reader.loadLogFiles(LOGPATH);
		results = new HashMap<File,List<String>>();
	}
	
	public static void main(String[] args) {
		LogAnalyzer analyzer = new LogAnalyzer();
		analyzer.processLogs();
		analyzer.printResults();
	}

	
	private void fillQuestions(){
		questions = new ArrayList<String>();
		questions.add("ID");
		questions.add("Jaguar task");
		questions.add("Jaguar 1st?");
		questions.add("Time spent in the Jaguar task");
		questions.add("Jaguar time gaps");
		questions.add("Jaguar is use in the beginning?");
		questions.add("Jaguar is use in the middle?");
		questions.add("Jaguar is use in the end?");
		questions.add("Time spent using Jaguar");
		questions.add("Time gaps using Jaguar");
		questions.add("Jaguar was used?");
		questions.add("How many times the Jaguar list was used?");
		questions.add("How many times the slider was used?");
		questions.add("How many times the text search was used?");
		questions.add("How many different methods/lines were inspected using Jaguar?");
		questions.add("How many times each method/line was inspected using Jaguar?");
		questions.add("How many shifts occurred between Jaguar and editor?");
	}
		
	public void processLogs(){
		for(File file : logList){
			List<String> responses = new ArrayList<String>();
			if(!file.isDirectory()){
				logContent = reader.readLog(file);
				//System.out.println(file.getName());
				preProcess();
				responses.add(getID());
				responses.add(getJaguarProject());
				responses.add(isJaguar1st());
				responses.add(timeSpentInJaguarTask());
				responses.add(jaguarTimeGaps());
				responses.add(jaguarIsUsedInTheBeginning());
				responses.add(jaguarIsUsedInTheMiddle());
				responses.add(jaguarIsUsedInTheEnd());
				responses.add(timeSpentUsingJaguar());
				responses.add(timeGapsUsingJaguar());
				responses.add(jaguarWasUsed());
				responses.add(countJaguarListUses());
				responses.add(countSliderUses());
				responses.add(countTextSearchUses());
				responses.add(countMethodsOrLinesInspectedUsingJaguar());
				responses.add(countUsesOfEachMethodOrLineUsingJaguar());
				responses.add(countShiftsBetweenJaguarAndEditor());
			}
			results.put(file, responses);
			break;
		}
	}
	
	private void preProcess(){
		countNumberOfStartsandStops();
		removeJTopasLines();
	}
	
	private void postProcess(){
		cleanNumberOfStartsAndStops();
	}
	
	
	private void countNumberOfStartsandStops(){
		for(String logLine : logContent){
			if(logLine.contains(START_JAGUAR)){
				numberOfJaguarStarts++;
				continue;
			}
			if(logLine.contains(STOP_JAGUAR)){
				numberOfJaguarStops++;
				continue;
			}
			if(logLine.contains(START_ECLIPSE)){
				numberOfEclipseStarts++;
				continue;
			}
			if(logLine.contains(STOP_ECLIPSE)){
				numberOfEclipseStops++;
				continue;
			}
		}
	}
	
	private void removeJTopasLines(){
		List<String> logContentTemp = new ArrayList<String>();
		//System.out.println("before:"+logContent.size());
		for(String logLine : logContent){
			if(!logLine.contains(IS_JTOPAS)){
				logContentTemp.add(logLine);
			}
		}
		logContent.clear();
		logContent.addAll(logContentTemp);
		//System.out.println("after:"+logContent.size());
	}
	
	private void cleanNumberOfStartsAndStops(){
		numberOfJaguarStarts = 0;
		numberOfJaguarStops = 0;
		numberOfEclipseStarts = 0;
		numberOfEclipseStops = 0;
	}
	
	private String getID(){
		for(String logLine : logContent){
			if(logLine.contains(IDNUMBER)){
				return logLine.substring((logLine.indexOf(IDNUMBER)+IDNUMBER.length()));
			}
		}
		return "";
	}
	
	private String getJaguarProject(){
		
		for(String logLine : logContent){
			if(logLine.contains(IS_JAGUAR)){
				if(logLine.contains(IS_JSOUP)){
					return JSOUP;
				}else if(logLine.contains(IS_XSTREAM)){
					return XSTREAM;
				}
				break;
			}
		}
		return "";
	}
	
	private String isJaguar1st(){
		boolean jaguar1st = false;
		for(String logLine : logContent){
			if(logLine.contains(IS_JAGUAR_1ST)){
				jaguar1st = true;
				break;
			}
			if(logLine.contains(ISNOT_JAGUAR_1ST)){ 
				jaguar1st = false;
				break;
			}
		}
		if(jaguar1st){
			return YES;
		}else{ 
			return NO;
		}
	}
	
	private String timeSpentInJaguarTask(){
		String startTime = "";
		String stopTime = "";
		
		for(String logLine : logContent){
			if(logLine.contains(START_JAGUAR)){
				if(startTime.isEmpty()){//get only the 1st occurrence
					startTime = logLine.substring(1,20);
				}
			}
			if(logLine.contains(STOP_JAGUAR)){
				stopTime = logLine.substring(1,20);
			}
		}
		return calculateTimeDiff(startTime, stopTime);
	}
	
	private String jaguarTimeGaps(){
		int countJaguarStops = 0;
		boolean collectDateTime = false;
		List<String> dateTimeList = new ArrayList<String>();
		
		for(String logLine : logContent){
			if(logLine.contains(START_JAGUAR)){
				collectDateTime = true;
			}
			if(collectDateTime){
				dateTimeList.add(logLine.substring(1,20));
			}
			if(logLine.contains(STOP_JAGUAR)){
				countJaguarStops++;
				if(countJaguarStops == numberOfJaguarStops && numberOfJaguarStarts == numberOfJaguarStops){
					collectDateTime = false;
					break;
				}
			}
			if(countJaguarStops == numberOfJaguarStops && numberOfJaguarStarts > numberOfJaguarStops && logLine.contains(START_JAGUAR) && collectDateTime){
				collectDateTime = false;
				break;
			}
		}
		return calculateTimeGaps(dateTimeList);
	}
	
	private String jaguarIsUsedInTheBeginning(){
		String startTime = "";
		String stopTime = "";
		
		for(String logLine : logContent){
			if(logLine.contains(START_JAGUAR)){
				if(startTime.isEmpty()){//get only the 1st occurrence
					startTime = logLine.substring(1,20);
				}
			}
			if(logLine.contains(STOP_JAGUAR)){
				stopTime = logLine.substring(1,20);
			}
		}
		
		long diffMili = calculateTimeDiffInMiliSeconds(startTime, stopTime);
		long startMili = 0;
		try {
			Date start = dateFormat.parse(startTime);
			startMili = start.getTime();
			for(String logLine : logContent){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD) || logLine.contains(CLICK_ON_JAGUAR_LINE) || logLine.contains(CLICK_ON_JAGUAR_SLIDER) || logLine.contains(CLICK_ON_JAGUAR_TEXT)){
					long currentTime = dateFormat.parse(logLine.substring(1,20)).getTime();
					if(currentTime < (startMili+(diffMili/3))){
						return YES;
					}
				}
			}
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return NO;
	}
	
	
	private String jaguarIsUsedInTheMiddle(){
		String startTime = "";
		String stopTime = "";
		
		for(String logLine : logContent){
			if(logLine.contains(START_JAGUAR)){
				if(startTime.isEmpty()){//get only the 1st occurrence
					startTime = logLine.substring(1,20);
				}
			}
			if(logLine.contains(STOP_JAGUAR)){
				stopTime = logLine.substring(1,20);
			}
		}
		
		long diffMili = calculateTimeDiffInMiliSeconds(startTime, stopTime);
		long startMili = 0;
		try {
			Date start = dateFormat.parse(startTime);
			startMili = start.getTime();
			for(String logLine : logContent){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD) || logLine.contains(CLICK_ON_JAGUAR_LINE) || logLine.contains(CLICK_ON_JAGUAR_SLIDER) || logLine.contains(CLICK_ON_JAGUAR_TEXT)){
					long currentTime = dateFormat.parse(logLine.substring(1,20)).getTime();
					if(currentTime >= (startMili+(diffMili/3)) && currentTime < (startMili+(2*diffMili/3))){
						return YES;
					}
				}
			}
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return NO;
	}
	
	private String jaguarIsUsedInTheEnd(){
		String startTime = "";
		String stopTime = "";
		
		for(String logLine : logContent){
			if(logLine.contains(START_JAGUAR)){
				if(startTime.isEmpty()){//get only the 1st occurrence
					startTime = logLine.substring(1,20);
				}
			}
			if(logLine.contains(STOP_JAGUAR)){
				stopTime = logLine.substring(1,20);
			}
		}
		
		long diffMili = calculateTimeDiffInMiliSeconds(startTime, stopTime);
		long startMili = 0;
		try {
			Date start = dateFormat.parse(startTime);
			startMili = start.getTime();
			for(String logLine : logContent){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD) || logLine.contains(CLICK_ON_JAGUAR_LINE) || logLine.contains(CLICK_ON_JAGUAR_SLIDER) || logLine.contains(CLICK_ON_JAGUAR_TEXT)){
					long currentTime = dateFormat.parse(logLine.substring(1,20)).getTime();
					if(currentTime > (startMili+(2*diffMili/3))){
						return YES;
					}
				}
			}
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return NO;
	}
	
	//until the last click on the stop button
	private String timeSpentUsingJaguar(){
		String initialTime = "";
		String finalTime = "";
		int countJaguarStops = 0;
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_JAGUAR_METHOD) || logLine.contains(CLICK_ON_JAGUAR_LINE) || logLine.contains(CLICK_ON_JAGUAR_SLIDER) || logLine.contains(CLICK_ON_JAGUAR_TEXT)){
				if(initialTime.isEmpty()){//get only the 1st occurrence
					initialTime = logLine.substring(1,20);
				}
				finalTime = logLine.substring(1,20);
			}
			if(logLine.contains(STOP_JAGUAR)){
				countJaguarStops++;
				if(countJaguarStops == numberOfJaguarStops){
					break;
				}
			}
		}
		
		return calculateTimeDiff(initialTime, finalTime);
	}
	
	private String timeGapsUsingJaguar(){
		int countJaguarStops = 0;
		boolean collectDateTime = false;
		List<String> dateTimeList = new ArrayList<String>();
		
		for(String logLine : logContent){
			if(logLine.contains(START_JAGUAR)){
				collectDateTime = true;
			}
			if(collectDateTime){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD) || logLine.contains(CLICK_ON_JAGUAR_LINE) || logLine.contains(CLICK_ON_JAGUAR_SLIDER) || logLine.contains(CLICK_ON_JAGUAR_TEXT)){
					dateTimeList.add(logLine.substring(1,20));
				}
			}
			if(logLine.contains(STOP_JAGUAR)){
				countJaguarStops++;
				if(countJaguarStops == numberOfJaguarStops && numberOfJaguarStarts == numberOfJaguarStops){
					collectDateTime = false;
					break;
				}
			}
			if(countJaguarStops == numberOfJaguarStops && numberOfJaguarStarts > numberOfJaguarStops && logLine.contains(START_JAGUAR) && collectDateTime){
				collectDateTime = false;
				break;
			}
		}
		return calculateTimeGaps(dateTimeList);
	}
	
	
	private String jaguarWasUsed(){
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_JAGUAR_METHOD) || logLine.contains(CLICK_ON_JAGUAR_LINE) || logLine.contains(CLICK_ON_JAGUAR_SLIDER) || logLine.contains(CLICK_ON_JAGUAR_TEXT)){
				return YES;
			}
		}
		return NO;
	}
	
	private String countJaguarListUses(){
		int jaguarUses = 0;
		
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_JAGUAR_METHOD) || logLine.contains(CLICK_ON_JAGUAR_LINE)){
				jaguarUses++;
			}
		}
		
		return String.valueOf(jaguarUses);
	}
	
	private String countSliderUses(){
		int sliderUses = 0;
		boolean sequentialUse = false;
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_JAGUAR_SLIDER)){
				if(!sequentialUse){
					sliderUses++;
					sequentialUse = true;
				}
			}else{
				sequentialUse = false;
			}
		}
		
		return String.valueOf(sliderUses);
	}
	
	
	private String countTextSearchUses(){
		int textSearchUses = 0;
		boolean sequentialUse = false;
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_JAGUAR_TEXT)){
				if(!sequentialUse){
					textSearchUses++;
					sequentialUse = true;
				}
			}else{
				sequentialUse = false;
			}
		}
		
		return String.valueOf(textSearchUses);
	}
	
	private String countMethodsOrLinesInspectedUsingJaguar(){
		Set<String> units = new HashSet<String>();
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
				String methodName = logLine.substring(logLine.indexOf(BEFORE_METHOD_NAME)+BEFORE_METHOD_NAME.length());
				units.add(methodName);
				System.out.println(methodName);
			}
			if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
				String lineNumber = logLine.substring(logLine.indexOf(BEFORE_LINE_NUMBER)+BEFORE_LINE_NUMBER.length());
				units.add(lineNumber);
				System.out.println(lineNumber);
			}
		}
		return String.valueOf(units.size());
	}
	
	private String countUsesOfEachMethodOrLineUsingJaguar(){
		Map<String,Integer> units = new HashMap<String,Integer>();
		String unitList = "";
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
				String methodName = logLine.substring(logLine.indexOf(BEFORE_METHOD_NAME)+BEFORE_METHOD_NAME.length());
				if(units.containsKey(methodName)){
					int counter = units.remove(methodName);
					counter++;
					units.put(methodName, counter);
				}else{
					units.put(methodName, 1);
				}
			}
			if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
				String lineNumber = logLine.substring(logLine.indexOf(BEFORE_LINE_NUMBER)+BEFORE_LINE_NUMBER.length());
				if(units.containsKey(lineNumber)){
					int counter = units.remove(lineNumber);
					counter++;
					units.put(lineNumber, counter);
				}else{
					units.put(lineNumber, 1);
				}
			}
		}
		units = LogMapUtil.sortByValue(units);
		Set<String> unitSet = units.keySet();
		for(String unit : unitSet){
			unitList += unit + " : " + units.get(unit) + "\n";
		}
		return unitList;
	}
	
	
	private String countShiftsBetweenJaguarAndEditor(){
		int swifts = 0;
		boolean jaguarClick = false;
		boolean checkEditorInteraction = false; //the line that should be an editor interaction
		for(String logLine : logContent){
			if(isJaguarMethod()){
				String methodName = "";
				if(jaguarClick){
					if(checkEditorInteraction){
						swifts++;
						checkEditorInteraction = false;
						jaguarClick = false;
						methodName = "";
						continue;
					}
					if(logLine.contains(EDITOR_CARET) || logLine.contains(METHOD_MOUSE_HOVER)){
						continue;
					}
					if(logLine.contains(EDITOR) && logLine.contains(methodName)){
						checkEditorInteraction = true;
						continue;
					}
				}
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
					jaguarClick = true;
					methodName = logLine.substring(logLine.indexOf(METHOD_NAME_BEGIN_INDEX)+1,logLine.indexOf(METHOD_NAME_END_INDEX));
					System.out.println("METHOD = "+methodName);
					
				}
			}else{
				String lineName = "";
				if(jaguarClick){
					if(checkEditorInteraction){
						swifts++;
						checkEditorInteraction = false;
						jaguarClick = false;
						lineName = "";
						continue;
					}
					if(logLine.contains(EDITOR_CARET) || logLine.contains(LINE_MOUSE_HOVER)){
						continue;
					}
					if(logLine.contains(EDITOR) && logLine.contains(lineName)){
						checkEditorInteraction = true;
						continue;
					}
				}
				if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
					jaguarClick = true;
					lineName = logLine.substring(logLine.indexOf(LINE_NAME_BEGIN_INDEX)+LINE_NAME_BEGIN_INDEX.length(),logLine.indexOf(LINE_NAME_END_INDEX));
					System.out.println("LINE = "+lineName);
					
				}
			}
		}
		
		return String.valueOf(swifts);
	}
	
		
	private String calculateTimeDiff(String start, String stop){
		String diff = "";
		long diffMili;
		try {
			Date startTime = dateFormat.parse(start);
			Date stopTime = dateFormat.parse(stop);
			diffMili = stopTime.getTime() - startTime.getTime();
			long diffHours = diffMili / (60 * 60 * 1000) % 60;
			long diffMinutes = diffMili / (60 * 1000) % 60;
			long diffSeconds = diffMili / 1000 % 60;
			diff = String.valueOf(diffHours)+":"+String.valueOf(diffMinutes)+":"+String.valueOf(diffSeconds);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return diff;
	}
	
	private String calculateTimeGaps(List<String> times){
		List<Long> timeGapList = new ArrayList<Long>(); 
		String orderedTimeGaps = "";
		try {
			for(int i = 0; i < times.size() - 1; i++){
				timeGapList.add((dateFormat.parse(times.get(i+1)).getTime())-(dateFormat.parse(times.get(i)).getTime()));
			}
			Collections.sort(timeGapList);
			Collections.reverse(timeGapList);
			for(Long timeGap : timeGapList){
				orderedTimeGaps += ((timeGap/(60*1000)%60)>0?(timeGap/(60*1000)%60)+":"+(timeGap/1000%60)+", ":(""));
			}
			
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return orderedTimeGaps;
	}
	
	
	private long calculateTimeDiffInMiliSeconds(String start, String stop){
		long diffMili = 0;
		try {
			Date startTime = dateFormat.parse(start);
			Date stopTime = dateFormat.parse(stop);
			diffMili = stopTime.getTime() - startTime.getTime();
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return diffMili;
	}
	
	private boolean isJaguarMethod(){
		for(String logLine : logContent){
			if(logLine.contains(IS_METHOD)){
				return true;
			}
		}
		return false;
	}
	
	public void printResults(){
		Set<File> resultSet = results.keySet();
		for(File file : resultSet){
			System.out.println(file.getName());
			List<String> resultInstance = results.get(file);
			for(String response : resultInstance){
				System.out.println(response);
			}
		}
	}
	

}
