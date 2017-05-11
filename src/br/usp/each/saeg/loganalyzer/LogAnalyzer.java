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

	private final String LOGPATH = "/home/higor/Dropbox/user-study/process-logs/";
	private LogReader reader;
	private File logList[];
	private List<String> logContent;
	private static Map<String,List<String>> results;
	private List<String> questions;
	private SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
	private SuspiciousCode suspiciousCode = new SuspiciousCode();
	
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
	private final String BEFORE_CLASSMETHOD_NAME = "[name=";
	private final String BEFORE_LINE_NUMBER = "[line=";
	private final String AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER = ", score=";
	
	private final String CLICK_ON_JAGUAR_METHOD = "[TableViewer] [Roadmap] click";
	private final String CLICK_ON_JAGUAR_LINE = "[TableViewer] [Line] click";
	private final String CLICK_ON_JAGUAR_TEXT = "[Text] change";
	private final String CLICK_ON_JAGUAR_SLIDER = "[Slider] changed";
	
	private final String EDITOR_CARET = "[EditorTracker] caret";
	private final String EDITOR = "[EditorTracker]";
	private final String CLICK_ON_EDITOR = "click @ line: ";
	private final String EDITOR_MOUSE_HOVER = "[mouse hover] @ line: ";
	private final String METHOD_MOUSE_HOVER = "[RoadmapLabelProvider] [Mouse hover]";
	private final String LINE_MOUSE_HOVER = "[RequirementLabelProvider] [Mouse hover]";
	private final String AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR = ", code: ";
	
	private final String DEBUG_START = "[DebugListener] debugging started";
	private final String DEBUG_STOP = "[DebugListener] debugging finished";
	private final String JUNIT_START = "[JUnitListener] JUnit session started";
	private final String JUNIT_STOP = "[JUnitListener] JUnit session finished";
	
	private final String TEST_CLASS_EDITOR_CLICK = "Test] "+CLICK_ON_EDITOR;
	private final String TEST_CLASS_EDITOR_HOVER = "Test] "+EDITOR_MOUSE_HOVER;
	private final String TEST_CLASS_NAME_PATTERN = "Test";
	
	private final String BREAKPOINT_ADDED = "[BreakpointListener] breakpoint [added]";
	private final String BREAKPOINT_REMOVED = "[BreakpointListener] breakpoint [removed]";
	private final String BREAKPOINT_LINENUMBER_SEPARATOR = ":";
	private final String BREAKPOINT_TESTCLASSNAME_SEPARATOR = ".";
	
	private final String METHOD_NAME_BEGIN_INDEX = ".";
	private final String METHOD_NAME_END_INDEX = ")";
	private final String LINE_NAME_BEGIN_INDEX = "content= \"";
	private final String LINE_NAME_END_INDEX = "\"]";
	
	private final String CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX = "[EditorTracker] [";
	private final String CLASS_NAME_FROM_EDITOR_CLICK_END_INDEX = "] click @ line";
		
	private final String JSOUP = "jsoup";
	private final String XSTREAM = "xstream";
	private final String LINE = "line";
	private final String METHOD = "method";
	private final String YES = "yes";
	private final String NO = "no";
	
	private final String CODE_METHOD_START_COMMENT = "/**";
	
	private int numberOfJaguarStarts = 0;
	private int numberOfJaguarStops = 0;
	private int numberOfEclipseStarts = 0;
	private int numberOfEclipseStops = 0;
	
	private long jaguarStartTime;
	private long jaguarStopTime;
	private long eclipseStartTime;
	private long eclipseStopTime;
	
	private String jaguarProgram = "";
	private String eclipseProgram = "";
	
	
	public LogAnalyzer(){
		reader = new LogReader();
		logList = reader.loadLogFiles(LOGPATH);
		results = new HashMap<String,List<String>>();
	}
	
	public static void main(String[] args) {
		LogAnalyzer analyzer = new LogAnalyzer();
		analyzer.fillQuestions();
		analyzer.processLogs();
		analyzer.printResults();
		LogWriter writer =  new LogWriter(results);
		writer.generateCSVFile();
	}

	
	private void fillQuestions(){
		questions = new ArrayList<String>();
		questions.add("ID");
		questions.add("Jaguar task");
		questions.add("Jaguar 1st?");
		questions.add("Time spent in the Jaguar task");
		questions.add("Time gaps for all interactions in the Jaguar task");
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
		questions.add("How many shifts occurred between Jaguar and JUnit?");
		questions.add("How many breakpoints are added after inspect Jaguar?");
		questions.add("How many times the faulty method/line was inspected using Jaguar?");
		questions.add("How many times the faulty line was inspected using the Editor for the Jaguars fault?");
		questions.add("How many times the faulty line was inspected using the Editor for the Eclipses fault?");
		questions.add("How many times the faulty method was inspected using the Editor for the Jaguars fault?");
		questions.add("How many times the faulty method was inspected using the Editor for the Eclipses fault?");
		questions.add("How many different scores were inspected?");
		questions.add("How many methods/lines were inspected in order?");
		questions.add("There were yellow methods/lines inspected?");
		questions.add("There were green methods/lines inspected?");
		questions.add("The most suspicious method/line was inspected first?");
		questions.add("Started using the roadmap?");
		questions.add("How many times the JUnit was ran in the Jaguar task?(Without running debugger)");
		questions.add("How many times the Debugger was ran in the Jaguar task?");
		questions.add("How many breakpoints were added in methods/lines of Jaguar?");
		questions.add("How many breakpoints were added in the Jaguar task's faulty method?");
		questions.add("How many breakpoints were added in the Jaguar task's faulty line?");
		questions.add("How many breakpoints were added in the Jaguar task? (All breakpoints)");
		questions.add("The bug was found immediately after click on roadmap/line list?");
		//Eclipse task questions
		questions.add("Time spent in the Eclipse task");
		questions.add("Time gaps using Eclipse");
		questions.add("How many times the JUnit was ran in the Eclipse task?(Without running debugger)");
		questions.add("How many times the Debugger was ran in the Eclipse task?");
		questions.add("How many breakpoints were added in the Eclipse task's faulty method?");
		questions.add("How many breakpoints were added in the Eclipse task's faulty line?");
		questions.add("How many breakpoints were added in the Eclipse task? (All breakpoints)");
		questions.add("How many methods were inspected in the Eclipse task?");
		questions.add("How many lines were inspected in the Eclipse task?");
		//aditional questions
		questions.add("How many lines were inspected using the Editor for the Jaguars fault?");
		questions.add("How many lines were inspected using the Editor for the Eclipses fault?");
		questions.add("How many methods were inspected using the Editor for the Jaguars fault?");
		questions.add("How many methods were inspected using the Editor for the Eclipses fault?");
		results.put("Questions", questions);
	}
		
	public void processLogs(){
		for(File file : logList){
			List<String> responses = new ArrayList<String>();
			if(!file.isDirectory()){
				logContent = reader.readLog(file);
				System.out.println(file.getName());
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
				responses.add(countShiftsBetweenJaguarAndJUnit());
				responses.add(countShiftsBetweenJaguarAndBreakpoints());
				responses.add(countClicksOnTheFaultyElementUsingJaguar());
				responses.add(countClicksOnTheFaultyLineUsingEditorInJaguarsFault());
				responses.add(countClicksOnTheFaultyLineUsingEditorInEclipsesFault());
				responses.add(countClicksOnTheFaultyMethodUsingEditorInJaguarsFault());
				responses.add(countClicksOnTheFaultyMethodUsingEditorInEclipsesFault());
				responses.add(countDifferentScoresInspected());
				responses.add(countMethodsOrLinesInspectedInOrder());
				responses.add(countYellowMethodsOrLinesInspected());
				responses.add(countGreenMethodsOrLinesInspected());
				responses.add(highestMethodOrLineInspectedFirst());
				responses.add(startedUsingJaguar());
				responses.add(countJUnitRunsInJaguarTask());
				responses.add(countDebuggerRunsInJaguarTask());
				responses.add(countBreakpointsAddedInJaguarsMethodsOrLines());
				responses.add(countBreakpointsAddedInJaguarTasksFaultyMethod());
				responses.add(countBreakpointsAddedInJaguarTasksFaultyLine());
				responses.add(countBreakpointsAddedInJaguarTask());
				responses.add(bugFoundImmediatelyAfterInspectJaguar());
				//Eclipse task questions
				responses.add(timeSpentInEclipseTask());
				responses.add(timeGapsUsingEclipse());
				responses.add(countJUnitRunsInEclipseTask());
				responses.add(countDebuggerRunsInEclipseTask());
				responses.add(countBreakpointsAddedInEclipseTasksFaultyMethod());
				responses.add(countBreakpointsAddedInEclipseTasksFaultyLine());
				responses.add(countBreakpointsAddedInEclipseTask());
				responses.add(countMethodsInspectedUsingEclipse());
				responses.add(countLinesInspectedUsingEclipse());
				//Aditional questions
				responses.add(countClicksOnAllLinesUsingEditorInJaguarsFault());
				responses.add(countClicksOnAllLinesUsingEditorInEclipsesFault());
				responses.add(countClicksOnAllMethodsUsingEditorInJaguarsFault());
				responses.add(countClicksOnAllMethodsUsingEditorInEclipsesFault());
				postProcess();
			}
			results.put(file.getName(), responses);
			//break;
		}
	}
	
	private void preProcess(){
		removeJTopasLines();
		countNumberOfStartsandStops();
		defineJaguarAndEclipsePrograms();
	}
	
	private void postProcess(){
		cleanNumberOfStartsAndStops();
		cleanJaguarAndEclipsePrograms();
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
	
	private void defineJaguarAndEclipsePrograms(){
		jaguarProgram = getJaguarProject();
		if(jaguarProgram.equals(JSOUP)){
			eclipseProgram = XSTREAM;
		}else{
			eclipseProgram = JSOUP;
		}
	}
	
	private void cleanJaguarAndEclipsePrograms(){
		jaguarProgram = "";
		eclipseProgram = "";
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
		//if start or stop buttons were not pushed
		if(startTime.isEmpty() || stopTime.isEmpty()){
			for(String logLine : logContent){
				if(logLine.contains(jaguarProgram)){
					if(startTime.isEmpty()){//get only the 1st occurrence
						startTime = logLine.substring(1,20);
					}
				}
				if(logLine.contains(jaguarProgram)){
					stopTime = logLine.substring(1,20);
				}
			}
		}
		//if there is no use of jaguar in log
		if(startTime.isEmpty() || stopTime.isEmpty()){
			return "";
		}
		return calculateTimeDiff(startTime, stopTime);
	}
	
	//for all interactions while using Jaguar
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
		if(dateTimeList.isEmpty()){
			return "";
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
		//if jaguar's start or stop buttons were not pushed 
		if(startTime.isEmpty()){
			for(String logLine : logContent){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD) || logLine.contains(CLICK_ON_JAGUAR_LINE) || logLine.contains(METHOD_MOUSE_HOVER) || logLine.contains(LINE_MOUSE_HOVER)){
					startTime = logLine.substring(1,20);
					break;
				}
			}
		}
		if(stopTime.isEmpty()){
			for(String logLine : logContent){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD) || logLine.contains(CLICK_ON_JAGUAR_LINE) || logLine.contains(METHOD_MOUSE_HOVER) || logLine.contains(LINE_MOUSE_HOVER)){
					stopTime = logLine.substring(1,20);
				}
			}
		}
		
		if(!startTime.isEmpty() && !stopTime.isEmpty()){
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
		
		//if jaguar's start or stop buttons were not pushed 
		if(startTime.isEmpty()){
			for(String logLine : logContent){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD) || logLine.contains(CLICK_ON_JAGUAR_LINE) || logLine.contains(METHOD_MOUSE_HOVER) || logLine.contains(LINE_MOUSE_HOVER)){
					startTime = logLine.substring(1,20);
					break;
				}
			}
		}
		if(stopTime.isEmpty()){
			for(String logLine : logContent){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD) || logLine.contains(CLICK_ON_JAGUAR_LINE) || logLine.contains(METHOD_MOUSE_HOVER) || logLine.contains(LINE_MOUSE_HOVER)){
					stopTime = logLine.substring(1,20);
				}
			}
		}
				
		if(!startTime.isEmpty() && !stopTime.isEmpty()){
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
		
		//if jaguar's start or stop buttons were not pushed 
		if(startTime.isEmpty()){
			for(String logLine : logContent){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD) || logLine.contains(CLICK_ON_JAGUAR_LINE) || logLine.contains(METHOD_MOUSE_HOVER) || logLine.contains(LINE_MOUSE_HOVER)){
					startTime = logLine.substring(1,20);
					break;
				}
			}
		}
		if(stopTime.isEmpty()){
			for(String logLine : logContent){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD) || logLine.contains(CLICK_ON_JAGUAR_LINE) || logLine.contains(METHOD_MOUSE_HOVER) || logLine.contains(LINE_MOUSE_HOVER)){
					stopTime = logLine.substring(1,20);
				}
			}
		}
				
		if(!startTime.isEmpty() && !stopTime.isEmpty()){
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
		if(initialTime.isEmpty() || finalTime.isEmpty()){
			return "";
		}
		return calculateTimeDiff(initialTime, finalTime);
	}
	
	//only for jaguar interactions
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
		if(dateTimeList.isEmpty()){
			return "";
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
				String methodName = logLine.substring(logLine.indexOf(BEFORE_CLASSMETHOD_NAME)+BEFORE_CLASSMETHOD_NAME.length());
				units.add(methodName);
				//System.out.println(methodName);
			}
			if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
				String lineNumber = logLine.substring(logLine.indexOf(BEFORE_LINE_NUMBER)+BEFORE_LINE_NUMBER.length());
				units.add(lineNumber);
				//System.out.println(lineNumber);
			}
		}
		return String.valueOf(units.size());
	}
	
	private String countUsesOfEachMethodOrLineUsingJaguar(){
		Map<String,Integer> units = new HashMap<String,Integer>();
		String unitList = "";
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
				String methodName = logLine.substring(logLine.indexOf(BEFORE_CLASSMETHOD_NAME)+BEFORE_CLASSMETHOD_NAME.length());
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
			unitList += unit.substring(0,unit.indexOf(",")) + ":" + units.get(unit) + ", ";
		}
		return unitList;
	}
	
	
	private String countShiftsBetweenJaguarAndEditor(){
		int swifts = 0;
		boolean jaguarClick = false;
		boolean checkEditorInteraction = false; //the line that should be an editor interaction
		String lineName = "";
		String lineNumber = "";
		String methodName = "";
		String classAndMethodName = "";
		for(String logLine : logContent){
			if(isJaguarMethod()){
				if(jaguarClick){
					if(checkEditorInteraction){
						if(logLine.contains(EDITOR)){
							if(logLine.contains(CLICK_ON_EDITOR)){
								String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
//								System.out.println("method:"+classAndMethodName+"abc");
//								System.out.println("clicked line:"+inspectedLine+"abc");
								if(suspiciousCode.editorActionIsInsideJSoupsInspectedMethod(classAndMethodName, Integer.parseInt(inspectedLine)) || suspiciousCode.editorActionIsInsideXStreamsInspectedMethod(classAndMethodName, Integer.parseInt(inspectedLine))){
									swifts++;
									//System.out.println("click:swifts");
								}
								checkEditorInteraction = false;
								jaguarClick = false;
								methodName = "";
								classAndMethodName = "";
								continue;
							}
							if(logLine.contains(EDITOR_MOUSE_HOVER)){
								String inspectedLine = logLine.substring(logLine.indexOf(EDITOR_MOUSE_HOVER)+EDITOR_MOUSE_HOVER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
//								System.out.println("method:"+classAndMethodName+"abc");
//								System.out.println("hovered line:"+inspectedLine+"abc");
								if(suspiciousCode.editorActionIsInsideJSoupsInspectedMethod(classAndMethodName, Integer.parseInt(inspectedLine)) || suspiciousCode.editorActionIsInsideXStreamsInspectedMethod(classAndMethodName, Integer.parseInt(inspectedLine))){
									swifts++;
									//System.out.println("hover:swifts");
								}
								checkEditorInteraction = false;
								jaguarClick = false;
								methodName = "";
								classAndMethodName = "";
								continue;
							}
						}else{
							if(!logLine.contains(METHOD_MOUSE_HOVER)){
								checkEditorInteraction = false;
								jaguarClick = false;
								methodName = "";
								classAndMethodName = "";
								continue;
							}
						}
					}
					if(logLine.contains(EDITOR_CARET) || logLine.contains(METHOD_MOUSE_HOVER)){
						continue;
					}
					if(logLine.contains(EDITOR) && logLine.contains(methodName)){
						checkEditorInteraction = true;
						continue;
					}
					if(logLine.contains(EDITOR) && !logLine.contains(methodName)){//if the inspected/hovered line is immediately after a click on jaguar
						if(logLine.contains(CLICK_ON_EDITOR)){
							String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
//							System.out.println("womethod:"+classAndMethodName+"abc");
//							System.out.println("woclicked line:"+inspectedLine+"abc");
							if(suspiciousCode.editorActionIsAfterJSoupsInspectedMethodSignature(classAndMethodName, Integer.parseInt(inspectedLine)) || suspiciousCode.editorActionIsAfterXStreamsInspectedMethodSignature(classAndMethodName, Integer.parseInt(inspectedLine))){
								swifts++;
								//System.out.println("woclick:swifts");
								jaguarClick = false;
								methodName = "";
								classAndMethodName = "";
								continue;
							}
						}
						if(logLine.contains(EDITOR_MOUSE_HOVER)){
							String inspectedLine = logLine.substring(logLine.indexOf(EDITOR_MOUSE_HOVER)+EDITOR_MOUSE_HOVER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
//							System.out.println("womethod:"+classAndMethodName+"abc");
//							System.out.println("wohovered line:"+inspectedLine+"abc");
							if(suspiciousCode.editorActionIsAfterJSoupsInspectedMethodSignature(classAndMethodName, Integer.parseInt(inspectedLine)) || suspiciousCode.editorActionIsAfterXStreamsInspectedMethodSignature(classAndMethodName, Integer.parseInt(inspectedLine))){
								swifts++;
								//System.out.println("wohover:swifts");
								jaguarClick = false;
								methodName = "";
								classAndMethodName = "";
								continue;
							}
						}
					}
				}
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
					jaguarClick = true;
					methodName = logLine.substring(logLine.indexOf(METHOD_NAME_BEGIN_INDEX)+1,logLine.indexOf(METHOD_NAME_END_INDEX));
					classAndMethodName = logLine.substring(logLine.indexOf(BEFORE_CLASSMETHOD_NAME)+BEFORE_CLASSMETHOD_NAME.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					//System.out.println("METHOD = "+classAndMethodName);
				}
			}else{
				if(jaguarClick){
					if(checkEditorInteraction){
						if(logLine.contains(EDITOR)){
							if(logLine.contains(CLICK_ON_EDITOR)){
								String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
//								System.out.println("line number:"+lineNumber+"abc");
//								System.out.println("clicked line:"+inspectedLine+"abc");
								if(suspiciousCode.editorActionIsInsideJSoupsInspectedLine(Integer.parseInt(lineNumber), Integer.parseInt(inspectedLine)) || suspiciousCode.editorActionIsInsideXStreamsInspectedLine(Integer.parseInt(lineNumber), Integer.parseInt(inspectedLine))){
									swifts++;
									//System.out.println("liclick:swifts");
								}
								checkEditorInteraction = false;
								jaguarClick = false;
								lineName = "";
								lineNumber = "";
								continue;
							}
							if(logLine.contains(EDITOR_MOUSE_HOVER)){
								String inspectedLine = logLine.substring(logLine.indexOf(EDITOR_MOUSE_HOVER)+EDITOR_MOUSE_HOVER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
//								System.out.println("line number:"+lineNumber+"abc");
//								System.out.println("hovered line:"+inspectedLine+"abc");
								if(suspiciousCode.editorActionIsInsideJSoupsInspectedLine(Integer.parseInt(lineNumber), Integer.parseInt(inspectedLine)) || suspiciousCode.editorActionIsInsideXStreamsInspectedLine(Integer.parseInt(lineNumber), Integer.parseInt(inspectedLine))){
									swifts++;
									//System.out.println("lihover:swifts");
								}
								checkEditorInteraction = false;
								jaguarClick = false;
								lineName = "";
								lineNumber = "";
								continue;
							}
						}else{
							if(!logLine.contains(LINE_MOUSE_HOVER)){
								checkEditorInteraction = false;
								jaguarClick = false;
								lineName = "";
								lineNumber = "";
								continue;
							}
						}
					}
					if(logLine.contains(EDITOR_CARET) || logLine.contains(LINE_MOUSE_HOVER)){
						continue;
					}
					if(logLine.contains(EDITOR) && logLine.contains(lineName)){
						checkEditorInteraction = true;
						continue;
					}
					if(logLine.contains(EDITOR) && !logLine.contains(lineName)){//if the inspected/hovered line is immediately after a click on jaguar
						if(logLine.contains(CLICK_ON_EDITOR)){
							String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
//							System.out.println("limethod:"+lineNumber);
//							System.out.println("liclicked line:"+inspectedLine);
							if(suspiciousCode.editorActionIsAfterJSoupsInspectedLineMethodSignature(Integer.parseInt(lineNumber), Integer.parseInt(inspectedLine)) || suspiciousCode.editorActionIsAfterXStreamsInspectedLineMethodSignature(Integer.parseInt(lineNumber), Integer.parseInt(inspectedLine))){
								swifts++;
								//System.out.println("liclick:swifts");
								jaguarClick = false;
								lineName = "";
								lineNumber = "";
								continue;
							}
						}
						if(logLine.contains(EDITOR_MOUSE_HOVER)){
							String inspectedLine = logLine.substring(logLine.indexOf(EDITOR_MOUSE_HOVER)+EDITOR_MOUSE_HOVER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
//							System.out.println("limethod:"+lineNumber);
//							System.out.println("lihovered line:"+inspectedLine);
							if(suspiciousCode.editorActionIsAfterJSoupsInspectedLineMethodSignature(Integer.parseInt(lineNumber), Integer.parseInt(inspectedLine)) || suspiciousCode.editorActionIsAfterXStreamsInspectedLineMethodSignature(Integer.parseInt(lineNumber), Integer.parseInt(inspectedLine))){
								swifts++;
								//System.out.println("lihover:swifts");
								jaguarClick = false;
								lineName = "";
								lineNumber = "";
								continue;
							}
						}
					}
				}
				if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
					jaguarClick = true;
					lineName = logLine.substring(logLine.indexOf(LINE_NAME_BEGIN_INDEX)+LINE_NAME_BEGIN_INDEX.length(),logLine.indexOf(LINE_NAME_END_INDEX));
					lineNumber = logLine.substring(logLine.indexOf(BEFORE_LINE_NUMBER)+BEFORE_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					//System.out.println("LINE = "+lineNumber);
				}
			}
		}
		
		return String.valueOf(swifts);
	}
	
	
	
	private String countShiftsBetweenJaguarAndJUnit(){
		int swifts = 0;
		boolean jaguarClick = false;
		boolean checkJUnitInteraction = false; //the line that should be an junit interaction
		String lineName = "";
		String methodName = "";
		for(String logLine : logContent){
			if(isJaguarMethod()){
				if(jaguarClick){
					if(checkJUnitInteraction){
						if(logLine.contains(DEBUG_START) || logLine.contains(TEST_CLASS_EDITOR_CLICK)  || logLine.contains(TEST_CLASS_EDITOR_HOVER)){//if junit is ran/inspected/hovered immediately after a click on jaguar
							swifts++;
//							System.out.println("method:"+methodName+"junit");
//							System.out.println("element:"+logLine+"junit");
//							System.out.println("junit:swifts");
							checkJUnitInteraction = false;
							jaguarClick = false;
							methodName = "";
							continue;
						}
						if(!logLine.contains(METHOD_MOUSE_HOVER)){
							checkJUnitInteraction = false;
							jaguarClick = false;
							methodName = "";
							continue;
						}
					}
					if(logLine.contains(EDITOR_CARET) || logLine.contains(METHOD_MOUSE_HOVER) || (logLine.contains(EDITOR_MOUSE_HOVER) && !logLine.contains(TEST_CLASS_EDITOR_HOVER))){
						continue;
					}
					if(logLine.contains(EDITOR) && logLine.contains(methodName)){
						checkJUnitInteraction = true;
						continue;
					}
					//check cases in which JUnit is used immediately after jaguar
				}
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
					jaguarClick = true;
					methodName = logLine.substring(logLine.indexOf(METHOD_NAME_BEGIN_INDEX)+1,logLine.indexOf(METHOD_NAME_END_INDEX));
					//System.out.println("METHOD = "+classAndMethodName);
				}
			}else{
				if(jaguarClick){
					if(checkJUnitInteraction){
						if(logLine.contains(DEBUG_START) || logLine.contains(TEST_CLASS_EDITOR_CLICK)  || logLine.contains(TEST_CLASS_EDITOR_HOVER)){//if junit is ran/inspected/hovered immediately after a click on jaguar
							swifts++;
//							System.out.println("line number:"+lineNumber+"abc");
//							System.out.println("logline:"+logLine+"abc");
//							System.out.println("junit:swifts");
							checkJUnitInteraction = false;
							jaguarClick = false;
							lineName = "";
							continue;
						}
						if(!logLine.contains(METHOD_MOUSE_HOVER)){
							checkJUnitInteraction = false;
							jaguarClick = false;
							lineName = "";
							continue;
						}
					}
					if(logLine.contains(EDITOR_CARET) || logLine.contains(METHOD_MOUSE_HOVER) || (logLine.contains(EDITOR_MOUSE_HOVER) && !logLine.contains(TEST_CLASS_EDITOR_HOVER))){
						continue;
					}
					if(logLine.contains(EDITOR) && logLine.contains(lineName)){
						checkJUnitInteraction = true;
						continue;
					}
					//check cases in which JUnit is used immediately after jaguar
				}
				if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
					jaguarClick = true;
					lineName = logLine.substring(logLine.indexOf(LINE_NAME_BEGIN_INDEX)+LINE_NAME_BEGIN_INDEX.length(),logLine.indexOf(LINE_NAME_END_INDEX));
					//System.out.println("LINE = "+lineName);
				}
			}
		}
		
		return String.valueOf(swifts);
	}
	
	//only if a breakpoint is added inside the same method
	private String countShiftsBetweenJaguarAndBreakpoints(){
		int swifts = 0;
		boolean jaguarClick = false;
		boolean checkBreakpointInteraction = false; //the line that contains a breakpoint interaction
		String lineName = "";
		String lineNumber = "";
		String methodName = "";
		String classAndMethodName = "";
		for(String logLine : logContent){
			if(isJaguarMethod()){
				if(jaguarClick){
					if(logLine.contains(BREAKPOINT_ADDED)){
						String toggledLine = logLine.substring(logLine.lastIndexOf(BREAKPOINT_LINENUMBER_SEPARATOR)+1);
	//					System.out.println("method:"+classAndMethodName+"abc");
						//System.out.println("toggled line:"+toggledLine+" breakpoint");
						if(suspiciousCode.jaguarActionIsAfterJSoupsInspectedMethodSignature(classAndMethodName, Integer.parseInt(toggledLine)) || suspiciousCode.jaguarActionIsAfterXStreamsInspectedMethodSignature(classAndMethodName, Integer.parseInt(toggledLine))){
							swifts++;
							//System.out.println("break:swifts");
							jaguarClick = false;
							continue;
						}
						//breakpoint added in a relates test class?
						String testClassName = logLine.substring(logLine.lastIndexOf(BREAKPOINT_TESTCLASSNAME_SEPARATOR)+1,logLine.lastIndexOf(BREAKPOINT_LINENUMBER_SEPARATOR));
						if(suspiciousCode.isJSoupsFailedTestClass(testClassName) || suspiciousCode.isXStreamsFailedTestClass(testClassName)){
							swifts++;
							//System.out.println("break:swifts");
							//System.out.println("testClassName:"+testClassName);
							jaguarClick = false;
							continue;
						}
					}
				}
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
					jaguarClick = true;
					//methodName = logLine.substring(logLine.indexOf(METHOD_NAME_BEGIN_INDEX)+1,logLine.indexOf(METHOD_NAME_END_INDEX));
					classAndMethodName = logLine.substring(logLine.indexOf(BEFORE_CLASSMETHOD_NAME)+BEFORE_CLASSMETHOD_NAME.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					//System.out.println("METHOD = "+methodName);
				}
			}else{
				if(jaguarClick){
					if(logLine.contains(BREAKPOINT_ADDED)){
						String toggledLine = logLine.substring(logLine.lastIndexOf(BREAKPOINT_LINENUMBER_SEPARATOR)+1);
//						System.out.println("method:"+classAndMethodName+"abc");
						//System.out.println("toggled line:"+toggledLine+" breakpoint");
						if(suspiciousCode.jaguarActionIsInsideJSoupsInspectedLine(Integer.parseInt(lineNumber), Integer.parseInt(toggledLine)) || suspiciousCode.jaguarActionIsInsideXStreamsInspectedLine(Integer.parseInt(lineNumber), Integer.parseInt(toggledLine))){
							swifts++;
							//System.out.println("break:swifts");
							//System.out.println("line number:"+lineNumber+"abc");
							//jaguarClick = false;
							continue;
						}
						//breakpoint added in a relates test class?
						String testClassName = logLine.substring(logLine.lastIndexOf(BREAKPOINT_TESTCLASSNAME_SEPARATOR)+1,logLine.lastIndexOf(BREAKPOINT_LINENUMBER_SEPARATOR));
						if(suspiciousCode.isJSoupsFailedTestClass(testClassName) || suspiciousCode.isXStreamsFailedTestClass(testClassName)){
							swifts++;
							//System.out.println("break:swifts");
							//System.out.println("testClassName:"+testClassName);
							//jaguarClick = false;
							continue;
						}
					}
				}
				if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
					jaguarClick = true;
					//lineName = logLine.substring(logLine.indexOf(LINE_NAME_BEGIN_INDEX)+LINE_NAME_BEGIN_INDEX.length(),logLine.indexOf(LINE_NAME_END_INDEX));
					lineNumber = logLine.substring(logLine.indexOf(BEFORE_LINE_NUMBER)+BEFORE_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					//System.out.println("LINE = "+lineName);
				}
			}
		}
		
		return String.valueOf(swifts);
	}
	
	
	public String countClicksOnTheFaultyElementUsingJaguar(){
		int clicks = 0;
		String classAndMethodName = "";
		String lineNumber = "";
		for(String logLine : logContent){
			if(isJaguarMethod()){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
					classAndMethodName = logLine.substring(logLine.indexOf(BEFORE_CLASSMETHOD_NAME)+BEFORE_CLASSMETHOD_NAME.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					if(suspiciousCode.clickOnJSoupsFaultyMethod(classAndMethodName) || suspiciousCode.clickOnXStreamsFaultyMethod(classAndMethodName)){
						clicks++;
					}
				}
			}else{
				if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
					lineNumber = logLine.substring(logLine.indexOf(BEFORE_LINE_NUMBER)+BEFORE_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					if(suspiciousCode.clickOnJSoupsFaultyLine(lineNumber) || suspiciousCode.clickOnXStreamsFaultyLine(lineNumber)){
						clicks++;
					}
				}
			}
		}
		return String.valueOf(clicks);
	}
	
	//counting consecutive clicks on the faulty line
/*	public String countClicksOnTheFaultyLineUsingEditorInJaguarsFault(){
		int clicks = 0;
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_EDITOR)){
				if(logLine.contains(jaguarProgram)){
					String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
					String inspectedCode = logLine.substring(logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR.length());
					if(jaguarProgram.equals(JSOUP)){
						//if(suspiciousCode.clickOnJSoupsFaultyLineOnEditor(inspectedLine) && suspiciousCode.isJSoupsFaultyCode(inspectedCode)){//1 - all clicks, only for same line and text
						if((suspiciousCode.clickOnJSoupsFaultyLineOnEditor(inspectedLine) && suspiciousCode.isJSoupsFaultyCode(inspectedCode)) || (suspiciousCode.isJSoupsFaultyCode(inspectedCode))){//2 - all clicks, same text, but line can change
							clicks++;
						}
					}else{
						//if(suspiciousCode.clickOnXStreamsFaultyLineOnEditor(inspectedLine) && suspiciousCode.isXStreamsFaultyCode(inspectedCode)){//1 - all clicks, only for same line and text
						if((suspiciousCode.clickOnXStreamsFaultyLineOnEditor(inspectedLine) && suspiciousCode.isXStreamsFaultyCode(inspectedCode)) || (suspiciousCode.isXStreamsFaultyCode(inspectedCode))){//2 - all clicks, same text, but line can change
									clicks++;
						}
					}
				}
			}
		}
		return String.valueOf(clicks);
	}*/
	
	//3 - not counting consecutive clicks on the faulty line
	public String countClicksOnTheFaultyLineUsingEditorInJaguarsFault(){
		int clicks = 0;
		String previousLine = "";
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_EDITOR)){
				if(logLine.contains(jaguarProgram)){
					String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
					String inspectedCode = logLine.substring(logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR.length());
					String inspectedClass = logLine.substring(logLine.indexOf(CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX)+CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX.length(),logLine.indexOf(CLASS_NAME_FROM_EDITOR_CLICK_END_INDEX));
					if(jaguarProgram.equals(JSOUP)){
						if(suspiciousCode.isJSoupsFaultyClass(inspectedClass)){
							if(inspectedLine.equals(previousLine) && suspiciousCode.containsJSoupsFaultyCode(inspectedCode)){
								continue;
							}else{
								if((suspiciousCode.containsJSoupsFaultyCode(inspectedCode))){//similar text, but line can change
									clicks++;
								}
								previousLine = inspectedLine;
							}
						}
					}else{
						if(suspiciousCode.isXStreamsFaultyClass(inspectedClass)){
							if(inspectedLine.equals(previousLine) && suspiciousCode.containsXStreamsFaultyCode(inspectedCode)){
								continue;
							}else{
								if(suspiciousCode.containsXStreamsFaultyCode(inspectedCode)){//similar text, but line can change
									clicks++;
								}
								previousLine = inspectedLine;
							}
						}
					}
				}
			}else{
				if(!logLine.contains(EDITOR_MOUSE_HOVER)){
					previousLine = "";
				}
			}
		}
		return String.valueOf(clicks);
	}
		
	
	//counting consecutive clicks on the faulty line
/*	public String countClicksOnTheFaultyLineUsingEditorInEclipsesFault(){
		int clicks = 0;
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_EDITOR)){
				if(logLine.contains(eclipseProgram)){
					String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
					String inspectedCode = logLine.substring(logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR.length());
					if(eclipseProgram.equals(JSOUP)){
						//if(suspiciousCode.clickOnJSoupsFaultyLineOnEditor(inspectedLine) && suspiciousCode.isJSoupsFaultyCode(inspectedCode)){//1 - all clicks, only for same line and text
						if((suspiciousCode.clickOnJSoupsFaultyLineOnEditor(inspectedLine) && suspiciousCode.isJSoupsFaultyCode(inspectedCode)) || (suspiciousCode.isJSoupsFaultyCode(inspectedCode))){//2 - all clicks, same text, but the line can change
							clicks++;
						}
					}else{
						//if(suspiciousCode.clickOnXStreamsFaultyLineOnEditor(inspectedLine) && suspiciousCode.isXStreamsFaultyCode(inspectedCode)){1 - all clicks, only for same line and text
						if((suspiciousCode.clickOnXStreamsFaultyLineOnEditor(inspectedLine) && suspiciousCode.isXStreamsFaultyCode(inspectedCode)) || (suspiciousCode.isXStreamsFaultyCode(inspectedCode))){//2 - all clicks, same text, but the line can change
							clicks++;
						}
					}
				}
			}
		}
		return String.valueOf(clicks);
	}*/
	
	//3 - not counting consecutive clicks on the faulty line
	public String countClicksOnTheFaultyLineUsingEditorInEclipsesFault(){
		int clicks = 0;
		String previousLine = "";
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_EDITOR)){
				if(logLine.contains(eclipseProgram)){
					String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
					String inspectedCode = logLine.substring(logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR.length());
					String inspectedClass = logLine.substring(logLine.indexOf(CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX)+CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX.length(),logLine.indexOf(CLASS_NAME_FROM_EDITOR_CLICK_END_INDEX));
					if(eclipseProgram.equals(JSOUP)){
						if(suspiciousCode.isJSoupsFaultyClass(inspectedClass)){
							if(inspectedLine.equals(previousLine) && suspiciousCode.containsJSoupsFaultyCode(inspectedCode)){
								continue;
							}else{
								if((suspiciousCode.containsJSoupsFaultyCode(inspectedCode))){//similar text, but line can change
									clicks++;
								}
								previousLine = inspectedLine;
							}
						}
					}else{
						if(suspiciousCode.isXStreamsFaultyClass(inspectedClass)){
							if(inspectedLine.equals(previousLine) && suspiciousCode.containsXStreamsFaultyCode(inspectedCode)){
								continue;
							}else{
								if(suspiciousCode.containsXStreamsFaultyCode(inspectedCode)){//similar text, but line can change
									clicks++;
								}
								previousLine = inspectedLine;
							}
						}
					}
				}
			}else{
				if(!logLine.contains(EDITOR_MOUSE_HOVER)){
					previousLine = "";
				}
			}
		}
		return String.valueOf(clicks);
	}


	//without counting consecutive clicks on the same line
	public String countClicksOnTheFaultyMethodUsingEditorInJaguarsFault(){
		int clicks = 0;
		String previousLine = "0";
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_EDITOR)){
				if(logLine.contains(jaguarProgram)){
					String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
					if(!previousLine.equals(inspectedLine)){
						if(jaguarProgram.equals(JSOUP)){
							if(suspiciousCode.editorActionIsInsideJSoupsInspectedMethod(suspiciousCode.JSOUP_FAULTY_METHOD, Integer.valueOf(inspectedLine))){
								clicks++;
							}
						}else{
							if(suspiciousCode.editorActionIsInsideXStreamsInspectedMethod(suspiciousCode.XSTREAM_FAULTY_METHOD, Integer.valueOf(inspectedLine))){
								clicks++;
							}
						}
						previousLine = inspectedLine;
					}
				}
			}
		}
		return String.valueOf(clicks);
	}
	
	//without counting consecutive clicks on the same line
	public String countClicksOnTheFaultyMethodUsingEditorInEclipsesFault(){
		int clicks = 0;
		String previousLine = "0";
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_EDITOR)){
				if(logLine.contains(eclipseProgram)){
					String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
					if(!previousLine.equals(inspectedLine)){
						if(eclipseProgram.equals(JSOUP)){
							if(suspiciousCode.editorActionIsInsideJSoupsInspectedMethod(suspiciousCode.JSOUP_FAULTY_METHOD, Integer.valueOf(inspectedLine))){
								clicks++;
							}
						}else{
							if(suspiciousCode.editorActionIsInsideXStreamsInspectedMethod(suspiciousCode.XSTREAM_FAULTY_METHOD, Integer.valueOf(inspectedLine))){
								clicks++;
							}
						}
						previousLine = inspectedLine;
					}
				}
			}
		}
		return String.valueOf(clicks);
	}
	
	//deeming two decimal places	
	public String countDifferentScoresInspected(){
		int numberSizeWithDecimalPlaces = 4;//except for score = 1.0 or 0.0 
		Map<String,Integer> scores = new HashMap<String, Integer>();
		String score = "";
		for(String logLine : logContent){
			if(isJaguarMethod()){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
					score = logLine.substring(logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER.length()+numberSizeWithDecimalPlaces);
					if(score.contains("]")){
						score = score.substring(0, score.length()-1);
					}
					if(scores.containsKey(score)){
						int counter = scores.remove(score);
						counter+=1;
						scores.put(score, counter);
					}else{
						scores.put(score, 1);
					}
				}
			}else{
				if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
					score = logLine.substring(logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER.length()+numberSizeWithDecimalPlaces);
					if(score.contains(",")){
						score = score.substring(0, score.length()-1);
					}
					if(scores.containsKey(score)){
						int counter = scores.remove(score);
						counter+=1;
						scores.put(score, counter);
					}else{
						scores.put(score, 1);
					}
				}
			}
		}
		Set<String> scoreSet = scores.keySet();
		//System.out.println("Inspections per score");
		//for(String counter : scoreSet){
			//System.out.println("score: "+counter+", inspections: "+scores.get(counter));
		//}
		return String.valueOf(scores.size());
	}
	
	//starting from the 1st position until break the order sequence
	public String countMethodsOrLinesInspectedInOrder(){
		int sequence = 0;
		String classAndMethodName = "";
		String lineNumber = "";
		String previousElement = "";
		for(String logLine : logContent){
			if(isJaguarMethod()){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
					classAndMethodName = logLine.substring(logLine.indexOf(BEFORE_CLASSMETHOD_NAME)+BEFORE_CLASSMETHOD_NAME.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					if(classAndMethodName.equals(previousElement)){
						continue;
					}
					if(jaguarProgram.equals(JSOUP)){
						if(sequence == suspiciousCode.getJSoupsMethodSequence().size()){
							break;
						}
						if(classAndMethodName.equals(suspiciousCode.getJSoupsMethodSequence().get(sequence))){
							sequence +=1;
							previousElement = classAndMethodName;
						}else{
							break;
						}
					}else{
						if(sequence == suspiciousCode.getXStreamsMethodSequence().size()){
							break;
						}
						if(classAndMethodName.equals(suspiciousCode.getXStreamsMethodSequence().get(sequence))){
							sequence +=1;
							previousElement = classAndMethodName;
						}else{
							break;
						}
					}
				}
			}else{
				if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
					lineNumber = logLine.substring(logLine.indexOf(BEFORE_LINE_NUMBER)+BEFORE_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					//System.out.println(">>>>linenumber: "+lineNumber+jaguarProgram);
					if(lineNumber.equals(previousElement)){
						continue;
					}
					if(jaguarProgram.equals(JSOUP)){
						if(sequence == suspiciousCode.getJSoupsLineSequence().size()){
							break;
						}
						if(lineNumber.equals(suspiciousCode.getJSoupsLineSequence().get(sequence))){
							sequence +=1;
							previousElement = lineNumber;
						}else{
							break;
						}
					}else{
						if(sequence == suspiciousCode.getXStreamsLineSequence().size()){
							break;
						}
						if(lineNumber.equals(suspiciousCode.getXStreamsLineSequence().get(sequence))){
							sequence +=1;
							previousElement = lineNumber;
						}else{
							break;
						}
					}
				}
			}
		}
		return String.valueOf(sequence);
	}
	
	
	//without repeating
	public String countYellowMethodsOrLinesInspected(){
		int clicks = 0;
		int numberSizeWithDecimalPlaces = 4;//except for score = 1.0 or 0.0 
		Set<String> yellowElements = new HashSet<String>();
		String score = "";
		String classAndMethodName = "";
		String lineNumber = "";
		for(String logLine : logContent){
			if(isJaguarMethod()){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
					score = logLine.substring(logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER.length()+numberSizeWithDecimalPlaces);
					classAndMethodName = logLine.substring(logLine.indexOf(BEFORE_CLASSMETHOD_NAME)+BEFORE_CLASSMETHOD_NAME.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					if(score.contains("]")){
						score = score.substring(0, score.length()-1);
					}
					if(!yellowElements.contains(classAndMethodName)){
						if(Double.valueOf(score)>0.25 && Double.valueOf(score)<=0.5){
							clicks+=1;
							yellowElements.add(classAndMethodName);
						}
					}
				}
			}else{
				if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
					score = logLine.substring(logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER.length()+numberSizeWithDecimalPlaces);
					lineNumber = logLine.substring(logLine.indexOf(BEFORE_LINE_NUMBER)+BEFORE_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));if(score.contains(","));
					if(score.contains(",")){
						score = score.substring(0, score.length()-1);
					}
					if(!yellowElements.contains(lineNumber)){
						if(Double.valueOf(score)>0.25 && Double.valueOf(score)<=0.5){
							clicks+=1;
							yellowElements.add(lineNumber);
						}
					}
				}
			}
		}
		return String.valueOf(clicks);
	}

	//without repeating
	public String countGreenMethodsOrLinesInspected(){
		int clicks = 0;
		int numberSizeWithDecimalPlaces = 4;//except for score = 1.0 or 0.0 
		Set<String> yellowElements = new HashSet<String>();
		String score = "";
		String classAndMethodName = "";
		String lineNumber = "";
		for(String logLine : logContent){
			if(isJaguarMethod()){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
					score = logLine.substring(logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER.length()+numberSizeWithDecimalPlaces);
					classAndMethodName = logLine.substring(logLine.indexOf(BEFORE_CLASSMETHOD_NAME)+BEFORE_CLASSMETHOD_NAME.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					if(score.contains("]")){
						score = score.substring(0, score.length()-1);
					}
					if(!yellowElements.contains(classAndMethodName)){
						if(Double.valueOf(score)<=0.25){
							clicks+=1;
							yellowElements.add(classAndMethodName);
						}
					}
				}
			}else{
				if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
					score = logLine.substring(logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER.length()+numberSizeWithDecimalPlaces);
					lineNumber = logLine.substring(logLine.indexOf(BEFORE_LINE_NUMBER)+BEFORE_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));if(score.contains(","));
					if(score.contains(",")){
						score = score.substring(0, score.length()-1);
					}
					if(!yellowElements.contains(lineNumber)){
						if(Double.valueOf(score)<=0.25){
							clicks+=1;
							yellowElements.add(lineNumber);
						}
					}
				}
			}
		}
		return String.valueOf(clicks);
	}
	
	public String highestMethodOrLineInspectedFirst(){
		String classAndMethodName = "";
		String lineNumber = "";
		for(String logLine : logContent){
			if(isJaguarMethod()){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
					classAndMethodName = logLine.substring(logLine.indexOf(BEFORE_CLASSMETHOD_NAME)+BEFORE_CLASSMETHOD_NAME.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					if(jaguarProgram.equals(JSOUP)){
						if(classAndMethodName.equals(suspiciousCode.getJSoupsMethodSequence().get(0))){
							return YES;
						}else{
							break;
						}
					}else{
						if(classAndMethodName.equals(suspiciousCode.getXStreamsMethodSequence().get(0))){
							return YES;
						}else{
							break;
						}
					}
				}
			}else{
				if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
					lineNumber = logLine.substring(logLine.indexOf(BEFORE_LINE_NUMBER)+BEFORE_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					if(jaguarProgram.equals(JSOUP)){
						if(lineNumber.equals(suspiciousCode.getJSoupsLineSequence().get(0))){
							return YES;
						}else{
							break;
						}
					}else{
						if(lineNumber.equals(suspiciousCode.getXStreamsLineSequence().get(0))){
							return YES;
						}else{
							break;
						}
					}
				}
			}
		}
		return NO;
	}
	
	public String startedUsingJaguar(){
		for(String logLine : logContent){
			if(isJaguarMethod()){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD) && logLine.contains(jaguarProgram)){
					return YES;
				}
				if(logLine.contains(DEBUG_START) && logLine.contains(jaguarProgram)){
					return NO;
				}
			}else{
				if(logLine.contains(CLICK_ON_JAGUAR_LINE) && logLine.contains(jaguarProgram)){
					return YES;
				}
				if(logLine.contains(DEBUG_START) && logLine.contains(jaguarProgram)){
					return NO;
				}
			}
		}
		return NO;
	}
	
	
	public String countJUnitRunsInJaguarTask(){
		int clicks = 0;
		boolean junitStarted = false;
		for(String logLine : logContent){
			if(logLine.contains(jaguarProgram) && logLine.contains(JUNIT_START)){
				junitStarted = true;
				continue;
			}
			if(logLine.contains(jaguarProgram) && logLine.contains(JUNIT_STOP) && junitStarted){
				clicks += 1;
			}
			if(logLine.contains(EDITOR_MOUSE_HOVER) || logLine.contains(METHOD_MOUSE_HOVER) || logLine.contains(LINE_MOUSE_HOVER)){
				continue;
			}
			junitStarted = false;
		}
		return String.valueOf(clicks);
	}
	
	public String countDebuggerRunsInJaguarTask(){
		int clicks = 0;
		boolean junitStarted = false;
		for(String logLine : logContent){
			if(logLine.contains(jaguarProgram) && logLine.contains(JUNIT_START)){
				junitStarted = true;
				continue;
			}
			if(logLine.contains(jaguarProgram) && !logLine.contains(JUNIT_STOP) && junitStarted){
				clicks += 1;
				if(logLine.contains(EDITOR_MOUSE_HOVER) || logLine.contains(METHOD_MOUSE_HOVER) || logLine.contains(LINE_MOUSE_HOVER)){
					clicks -= 1;
				}
			}
			junitStarted = false;
		}
		return String.valueOf(clicks);
	}
	
	public String countBreakpointsAddedInJaguarsMethodsOrLines(){
		int counter = 0;
		for(String logLine : logContent){
			if(logLine.contains(BREAKPOINT_ADDED) && logLine.contains(jaguarProgram)){
				String toggledLine = logLine.substring(logLine.lastIndexOf(BREAKPOINT_LINENUMBER_SEPARATOR)+1);
				if(isJaguarMethod()){
					String className = logLine.substring(logLine.lastIndexOf(BREAKPOINT_TESTCLASSNAME_SEPARATOR)+1,logLine.lastIndexOf(BREAKPOINT_LINENUMBER_SEPARATOR));
					if(suspiciousCode.lineBelongsToAnyJSoupMethodInJaguar(className, Integer.parseInt(toggledLine)) || suspiciousCode.lineBelongsToAnyXStreamMethodInJaguar(className, Integer.parseInt(toggledLine))){
						counter++;
						continue;
					}
				}else{
					if(suspiciousCode.lineBelongsToAnyJSoupLineInJaguar(Integer.parseInt(toggledLine)) || suspiciousCode.lineBelongsToAnyXStreamLineInJaguar(Integer.parseInt(toggledLine))){
						counter++;
						continue;
					}
				}
			}
		}
		return String.valueOf(counter);
	}
	
	public String countBreakpointsAddedInJaguarTasksFaultyMethod(){
		int counter = 0;
		for(String logLine : logContent){
			if(logLine.contains(BREAKPOINT_ADDED) && logLine.contains(jaguarProgram)){
				String toggledLine = logLine.substring(logLine.lastIndexOf(BREAKPOINT_LINENUMBER_SEPARATOR)+1);
				String className = logLine.substring(logLine.lastIndexOf(BREAKPOINT_TESTCLASSNAME_SEPARATOR)+1,logLine.lastIndexOf(BREAKPOINT_LINENUMBER_SEPARATOR));
				if(suspiciousCode.lineBelongsToJSoupsFaultyMethod(className, Integer.parseInt(toggledLine)) || suspiciousCode.lineBelongsToXStreamsFaultyMethod(className, Integer.parseInt(toggledLine))){
					counter++;
					continue;
				}
			}
		}
		return String.valueOf(counter);
	}
	
	public String countBreakpointsAddedInJaguarTasksFaultyLine(){
		int counter = 0;
		for(String logLine : logContent){
			if(logLine.contains(BREAKPOINT_ADDED) && logLine.contains(jaguarProgram)){
				String toggledLine = logLine.substring(logLine.lastIndexOf(BREAKPOINT_LINENUMBER_SEPARATOR)+1);
				if(jaguarProgram.equals(JSOUP) && suspiciousCode.clickOnJSoupsFaultyLine(toggledLine)){
					counter++;
					continue;
				}
				if(jaguarProgram.equals(XSTREAM) && suspiciousCode.clickOnXStreamsFaultyLine(toggledLine)){
					counter++;
					continue;
				}
			}
		}
		return String.valueOf(counter);
	}
	
	public String countBreakpointsAddedInJaguarTask(){
		int counter = 0;
		for(String logLine : logContent){
			if(logLine.contains(BREAKPOINT_ADDED) && logLine.contains(jaguarProgram)){
				counter++;
			}
		}
		return String.valueOf(counter);
	}
	
	//The bug is deemed as found immediately if the last jaguar action occurred in the faulty method/line, 
	//even if junit is ran once more to check or the faulty line is checked on editor
	//this method is not precise, it just indicates possible perfect bug detections. It must be verified manually
	public String bugFoundImmediatelyAfterInspectJaguar(){
		boolean faultyElement = false;
		String classAndMethodName = "";
		String lineNumber = "";
		for(String logLine : logContent){
			if(isJaguarMethod()){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
					if(faultyElement){
						return NO;
					}
					classAndMethodName = logLine.substring(logLine.indexOf(BEFORE_CLASSMETHOD_NAME)+BEFORE_CLASSMETHOD_NAME.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					if(suspiciousCode.clickOnJSoupsFaultyMethod(classAndMethodName) || suspiciousCode.clickOnXStreamsFaultyMethod(classAndMethodName)){
						faultyElement = true;
					}
				}
			}else{
				if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
					if(faultyElement){
						return NO;
					}
					lineNumber = logLine.substring(logLine.indexOf(BEFORE_LINE_NUMBER)+BEFORE_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
					if(jaguarProgram.equals(JSOUP) && suspiciousCode.clickOnJSoupsFaultyLine(lineNumber)){
						faultyElement = true;
					}
					if(jaguarProgram.equals(XSTREAM) && suspiciousCode.clickOnXStreamsFaultyLine(lineNumber)){
						faultyElement = true;
					}
				}
			}
		}
		if(faultyElement){
			return YES;
		}
		return NO;
	}
	
	
	//TODO:BASIC STRUCTURE
	public String basicStructure(){
		int clicks = 0;
		String classAndMethodName = "";
		String lineNumber = "";
		for(String logLine : logContent){
			if(isJaguarMethod()){
				if(logLine.contains(CLICK_ON_JAGUAR_METHOD)){
					classAndMethodName = logLine.substring(logLine.indexOf(BEFORE_CLASSMETHOD_NAME)+BEFORE_CLASSMETHOD_NAME.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
				}
			}else{
				if(logLine.contains(CLICK_ON_JAGUAR_LINE)){
					lineNumber = logLine.substring(logLine.indexOf(BEFORE_LINE_NUMBER)+BEFORE_LINE_NUMBER.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER));
				}
			}
		}
		return String.valueOf(clicks);
	}
	
	
	//Eclipse task questions
	
	private String timeSpentInEclipseTask(){
		String startTime = "";
		String stopTime = "";
		
		for(String logLine : logContent){
			if(logLine.contains(START_ECLIPSE)){
				if(startTime.isEmpty()){//get only the 1st occurrence
					startTime = logLine.substring(1,20);
				}
			}
			if(logLine.contains(STOP_ECLIPSE)){
				stopTime = logLine.substring(1,20);
			}
		}
		//if start or stop buttons were not pushed
		if(startTime.isEmpty() || stopTime.isEmpty()){
			for(String logLine : logContent){
				if(logLine.contains(eclipseProgram)){
					if(startTime.isEmpty()){//get only the 1st occurrence
						startTime = logLine.substring(1,20);
					}
				}
				if(logLine.contains(eclipseProgram)){
					stopTime = logLine.substring(1,20);
				}
			}
		}
		//if there is no use of eclipse in log
		if(startTime.isEmpty() || stopTime.isEmpty()){
			return "";
		}
		return calculateTimeDiff(startTime, stopTime);
	}
		
	private String timeGapsUsingEclipse(){
		int countEclipseStops = 0;
		boolean collectDateTime = false;
		List<String> dateTimeList = new ArrayList<String>();
		
		for(String logLine : logContent){
			if(logLine.contains(START_ECLIPSE)){
				collectDateTime = true;
			}
			if(collectDateTime){
				if(logLine.contains(CLICK_ON_EDITOR) || logLine.contains(DEBUG_START)){
					dateTimeList.add(logLine.substring(1,20));
				}
			}
			if(logLine.contains(STOP_ECLIPSE)){
				countEclipseStops++;
				if(countEclipseStops == numberOfEclipseStops && numberOfEclipseStarts == numberOfEclipseStops){
					collectDateTime = false;
					break;
				}
			}
			if(countEclipseStops == numberOfEclipseStops && numberOfEclipseStarts > numberOfEclipseStops && logLine.contains(START_ECLIPSE) && collectDateTime){
				collectDateTime = false;
				break;
			}
		}
		if(dateTimeList.isEmpty()){
			return "";
		}
		return calculateTimeGaps(dateTimeList);
	}
	
	public String countJUnitRunsInEclipseTask(){
		int clicks = 0;
		boolean junitStarted = false;
		for(String logLine : logContent){
			if(logLine.contains(eclipseProgram) && logLine.contains(JUNIT_START)){
				junitStarted = true;
				continue;
			}
			if(logLine.contains(eclipseProgram) && logLine.contains(JUNIT_STOP) && junitStarted){
				clicks += 1;
			}
			if(!logLine.contains(EDITOR_MOUSE_HOVER)){
				junitStarted = false;
			}
		}
		return String.valueOf(clicks);
	}
	
	public String countDebuggerRunsInEclipseTask(){
		int clicks = 0;
		boolean junitStarted = false;
		for(String logLine : logContent){
			if(logLine.contains(eclipseProgram) && logLine.contains(JUNIT_START)){
				junitStarted = true;
				continue;
			}
			if(logLine.contains(eclipseProgram) && !logLine.contains(JUNIT_STOP) && junitStarted){
				clicks += 1;
				if(logLine.contains(EDITOR_MOUSE_HOVER)){
					clicks -= 1;
				}
			}
			junitStarted = false;
		}
		return String.valueOf(clicks);
	}
	
	public String countBreakpointsAddedInEclipseTasksFaultyMethod(){
		int counter = 0;
		for(String logLine : logContent){
			if(logLine.contains(BREAKPOINT_ADDED) && logLine.contains(eclipseProgram)){
				String toggledLine = logLine.substring(logLine.lastIndexOf(BREAKPOINT_LINENUMBER_SEPARATOR)+1);
				String className = logLine.substring(logLine.lastIndexOf(BREAKPOINT_TESTCLASSNAME_SEPARATOR)+1,logLine.lastIndexOf(BREAKPOINT_LINENUMBER_SEPARATOR));
				if(suspiciousCode.lineBelongsToJSoupsFaultyMethod(className, Integer.parseInt(toggledLine)) || suspiciousCode.lineBelongsToXStreamsFaultyMethod(className, Integer.parseInt(toggledLine))){
					counter++;
					continue;
				}
			}
		}
		return String.valueOf(counter);
	}
	
	public String countBreakpointsAddedInEclipseTasksFaultyLine(){
		int counter = 0;
		for(String logLine : logContent){
			if(logLine.contains(BREAKPOINT_ADDED) && logLine.contains(eclipseProgram)){
				String toggledLine = logLine.substring(logLine.lastIndexOf(BREAKPOINT_LINENUMBER_SEPARATOR)+1);
				if(eclipseProgram.equals(JSOUP) && suspiciousCode.clickOnJSoupsFaultyLine(toggledLine)){
					counter++;
					continue;
				}
				if(eclipseProgram.equals(XSTREAM) && suspiciousCode.clickOnXStreamsFaultyLine(toggledLine)){
					counter++;
					continue;
				}
			}
		}
		return String.valueOf(counter);
	}
	
	public String countBreakpointsAddedInEclipseTask(){
		int counter = 0;
		for(String logLine : logContent){
			if(logLine.contains(BREAKPOINT_ADDED) && logLine.contains(eclipseProgram)){
				counter++;
			}
		}
		return String.valueOf(counter);
	}
	
	//only methods in the Jaguar list that are in the SuspiciousCode class 
	public String countMethodsInspectedUsingEclipse(){
		int counter = 0;
		Set<String> methods = new HashSet<String>();
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_EDITOR) && logLine.contains(eclipseProgram)){
				String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
				String className = logLine.substring(logLine.lastIndexOf(CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX)+CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX.length(),logLine.lastIndexOf(CLASS_NAME_FROM_EDITOR_CLICK_END_INDEX));
				//System.out.println("method >>> line and class: "+inspectedLine+", "+className);
				int lineNumber = Integer.valueOf(inspectedLine);
				String method = "";
				if(eclipseProgram.equals(JSOUP)){
					method = suspiciousCode.getJSoupMethodInEclipse(className, lineNumber);
				}else{
					method = suspiciousCode.getXStreamMethodInEclipse(className, lineNumber);
				}
				if(!method.isEmpty()){
					methods.add(method);
				}
			}
		}
		return String.valueOf(methods.size());
	}
	
	
	//only lines from methods in the Jaguar list that are in the SuspiciousCode class, except for initial lines 
	public String countLinesInspectedUsingEclipse(){
		int counter = 0;
		Map<Integer,Set<String>> lines = new HashMap<Integer,Set<String>>();
		Set<String> methods = new HashSet<String>();
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_EDITOR) && logLine.contains(eclipseProgram)){
				String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
				String className = logLine.substring(logLine.lastIndexOf(CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX)+CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX.length(),logLine.lastIndexOf(CLASS_NAME_FROM_EDITOR_CLICK_END_INDEX));
				int lineNumber = Integer.valueOf(inspectedLine);
				//System.out.println("line >>> line and class: "+inspectedLine+", "+className);
				if(!className.endsWith("Test")){
					if(suspiciousCode.lineBelongsToAnyJSoupMethodInJaguarUsingEditor(className, lineNumber) || suspiciousCode.lineBelongsToAnyXStreamMethodInJaguarUsingEditor(className, lineNumber)){
						int line = Integer.valueOf(inspectedLine);
						if(lines.containsKey(line)){
							//System.out.println("line >>> line: "+inspectedLine+", "+className);
							Set<String> classes = lines.remove(line);
							classes.add(className);
							lines.put(line, classes);
						}else{
							Set<String> clazz = new HashSet<String>();
							clazz.add(className);
							lines.put(line, clazz);
							//System.out.println("add line >>> line: "+inspectedLine+", "+className);
						}
					}
				}
			}
		}
		Set<Integer> lineSet = lines.keySet();
		for(int line : lineSet){
			counter += lines.get(line).size();
		}
		return String.valueOf(counter);
	}
	
	//Aditional questions
	
	public String countClicksOnAllLinesUsingEditorInJaguarsFault(){
		int clicks = 0;
		String previousLine = "";
		String previousClass = "";
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_EDITOR)){
				if(logLine.contains(jaguarProgram)){
					String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
					String inspectedClass = logLine.substring(logLine.indexOf(CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX)+CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX.length(),logLine.indexOf(CLASS_NAME_FROM_EDITOR_CLICK_END_INDEX));
					String inspectedCode = logLine.substring(logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR.length());
					if(inspectedLine.equals(previousLine) && inspectedClass.equals(previousClass)){
						continue;
					}else{
						if(!inspectedClass.endsWith(TEST_CLASS_NAME_PATTERN) && !inspectedCode.contains(CODE_METHOD_START_COMMENT)){
							clicks++;
						}
						previousLine = inspectedLine;
						previousClass = inspectedClass;
					}
				}
			}else{
				if(!logLine.contains(EDITOR_MOUSE_HOVER)){
					previousLine = "";
					previousClass = "";
				}
			}
		}
		return String.valueOf(clicks);
	}
	
	public String countClicksOnAllLinesUsingEditorInEclipsesFault(){
		int clicks = 0;
		String previousLine = "";
		String previousClass = "";
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_EDITOR)){
				if(logLine.contains(eclipseProgram)){
					String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
					String inspectedClass = logLine.substring(logLine.indexOf(CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX)+CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX.length(),logLine.indexOf(CLASS_NAME_FROM_EDITOR_CLICK_END_INDEX));
					String inspectedCode = logLine.substring(logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR)+AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR.length());
					if(inspectedLine.equals(previousLine) && inspectedClass.equals(previousClass)){
						continue;
					}else{
						if(!inspectedClass.endsWith(TEST_CLASS_NAME_PATTERN) && !inspectedCode.contains(CODE_METHOD_START_COMMENT)){
							clicks++;
						}
						previousLine = inspectedLine;
						previousClass = inspectedClass;
					}
				}
			}else{
				if(!logLine.contains(EDITOR_MOUSE_HOVER)){
					previousLine = "";
					previousClass = "";
				}
			}
		}
		return String.valueOf(clicks);
	}
	
	
	//not counting consecutive clicks on the same line
	public String countClicksOnAllMethodsUsingEditorInJaguarsFault(){
		int clicks = 0;
		String previousLine = "";
		String previousClass = "";
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_EDITOR)){
				if(logLine.contains(jaguarProgram)){
					String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
					int lineNumber = Integer.parseInt(inspectedLine);
					String inspectedClass = logLine.substring(logLine.indexOf(CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX)+CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX.length(),logLine.indexOf(CLASS_NAME_FROM_EDITOR_CLICK_END_INDEX));
					if(inspectedLine.equals(previousLine) && inspectedClass.equals(previousClass)){
						continue;
					}else{
						if(suspiciousCode.lineBelongsToAnyJSoupMethodInJaguarUsingEditor(inspectedClass,lineNumber) || suspiciousCode.lineBelongsToAnyXStreamMethodInJaguarUsingEditor(inspectedClass,lineNumber)){
							clicks++;
						}
						previousLine = inspectedLine;
						previousClass = inspectedClass;
					}
				}
			}else{
				if(!logLine.contains(EDITOR_MOUSE_HOVER)){
					previousLine = "";
					previousClass = "";
				}
			}
		}
		return String.valueOf(clicks);
	}
	
	public String countClicksOnAllMethodsUsingEditorInEclipsesFault(){
		int clicks = 0;
		String previousLine = "";
		String previousClass = "";
		for(String logLine : logContent){
			if(logLine.contains(CLICK_ON_EDITOR)){
				if(logLine.contains(eclipseProgram)){
					String inspectedLine = logLine.substring(logLine.indexOf(CLICK_ON_EDITOR)+CLICK_ON_EDITOR.length(),logLine.indexOf(AFTER_CLASSMETHOD_NAME_OR_LINE_NUMBER_ON_EDITOR));
					int lineNumber = Integer.parseInt(inspectedLine);
					String inspectedClass = logLine.substring(logLine.indexOf(CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX)+CLASS_NAME_FROM_EDITOR_CLICK_BEGIN_INDEX.length(),logLine.indexOf(CLASS_NAME_FROM_EDITOR_CLICK_END_INDEX));
					if(inspectedLine.equals(previousLine) && inspectedClass.equals(previousClass)){
						continue;
					}else{
						if(suspiciousCode.lineBelongsToAnyJSoupMethodInJaguarUsingEditor(inspectedClass,lineNumber) || suspiciousCode.lineBelongsToAnyXStreamMethodInJaguarUsingEditor(inspectedClass,lineNumber)){
							clicks++;
						}
						previousLine = inspectedLine;
						previousClass = inspectedClass;
					}
				}
			}else{
				if(!logLine.contains(EDITOR_MOUSE_HOVER)){
					previousLine = "";
					previousClass = "";
				}
			}
		}
		return String.valueOf(clicks);
	}
	
	
	
	//Auxiliary methods
		
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
		Set<String> resultSet = results.keySet();
		for(String file : resultSet){
			System.out.println(file);
			List<String> resultInstance = results.get(file);
			for(String response : resultInstance){
				System.out.println(response);
			}
		}
	}
	
}
