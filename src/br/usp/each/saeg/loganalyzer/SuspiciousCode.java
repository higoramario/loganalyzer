package br.usp.each.saeg.loganalyzer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class SuspiciousCode {
	
	/*
	 * There are two line number sequences: clicks on lists and mouse hovers take a number, 
	 * while clicks on the editor take a small number that varies with the amount of lines 
	 * of the initial class comments
	 * int[6]: 0-method's 1st line, including comment lines, for jaguar lists, hovering, and breakpoints
	 *         1-method's last line for jaguar, hovering, and breakpoints
	 *         2-method's 1st line, including method comments, for editor clicks
	 *         3-method's last line for editor clicks
	 *         4-method's signature line for jaguar lists, hovering, and breakpoints
	 *         5-method's signature line for editor clicks
	 *         
	 * For lines, a line has its respective number for jaguar lists and editor
	 * int[7]: 0-clicked number on editor
	 *         1-method's 1st line, including comment lines, for jaguar lists, hovering, and breakpoints
	 *         2-method's last line for jaguar, hovering, and breakpoints
	 *         3-method's 1st line, including method comments, for editor clicks and hovering
	 *         4-method's last line for editor clicks and hovering
	 *         5-method's signature line for jaguar lists, hovering, and breakpoints
	 *         6-method's signature line for editor clicks
	 *         
	 * */
	
	public static Map<String,int[]> jsoupMethods;
	public static Map<String,int[]> xstreamMethods;
	
	public static Map<Integer,int[]> jsoupLines;
	public static Map<Integer,int[]> xstreamLines;
	
	public static List<String> jsoupMethodSequence = new ArrayList<String>();
	public static List<String> xstreamMethodSequence = new ArrayList<String>();
	
	public static List<String> jsoupLineSequence = new ArrayList<String>();
	public static List<String> xstreamLineSequence = new ArrayList<String>();
	
	public static String JSOUP_FAILED_TESTCLASS = "ElementTest";//methods: testElementSiblingIndexSameContent(), testGetSiblingsWithDuplicateContent()
	public static String XSTREAM_FAILED_TESTCLASS = "ParametrizedConverterTest";//methods: testSameConverterWithDifferentType(), testAnnotationForConvertersWithParameters(), testCanUseCurrentTypeAsParameter(), testConverterWithSecondTypeParameter(), testAnnotatedJavaBeanConverter()
	
	public static String JSOUP_FAULTY_METHOD = "Element.indexInList(Element,Index<E>)";
	public static String JSOUP_FAULTY_LINE = "574";
	public static String JSOUP_FAULTY_LINE_ON_EDITOR = "566";
	public static String JSOUP_FAULTY_CODE = "if (element.equals(search))";
	public static String JSOUP_FAULTY_CODE_CHUNK = "if (element";
	public static String JSOUP_FAULTY_CLASS = "Element";
	public static String XSTREAM_FAULTY_METHOD = "AnnotationMapper.cacheConverter(XStreamConverter,Class)";
	public static String XSTREAM_FAULTY_LINE = "454";
	public static String XSTREAM_FAULTY_LINE_ON_EDITOR = "411";
	public static String XSTREAM_FAULTY_CODE = "if (targetType == null) {";
	public static String XSTREAM_FAULTY_CODE_CHUNK = "if (targetType";
	public static String XSTREAM_FAULTY_CLASS = "AnnotationMapper";
	
	private final int FIRSTLINE_METHOD_HOVER = 0;
	private final int LASTLINE_METHOD_HOVER = 1;
	private final int FIRSTLINE_METHOD_CLICK = 2;
	private final int LASTLINE_METHOD_CLICK = 3;
	private final int METHOD_SIGNATURE_HOVER = 4;
	private final int METHOD_SIGNATURE_CLICK = 5;
	
	private final int LINE_CLICK = 0;
	private final int FIRSTLINE_LINE_HOVER = 1;
	private final int LASTLINE_LINE_HOVER = 2;
	private final int FIRSTLINE_LINE_CLICK = 3;
	private final int LASTLINE_LINE_CLICK = 4;
	private final int METHOD_SIGNATURE_LINE_HOVER = 5;
	private final int METHOD_SIGNATURE_LINE_CLICK = 6;
	
	private static final int JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE = 8;
	private static final int JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE = 2;
	private static final int JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE = 3;
	private static final int JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE = 11;
	private static final int JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE = 1;
	private static final int JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE = 3;
	private static final int JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE = 0;
	private static final int JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE = 1;
	private static final int JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE = 5;
	private static final int JSOUP_NODETRAVERSOR_CLASS_EDITOR_NUMBER_DIFFERENCE = 0;
	private static final int JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE = 8;
	private static final int JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE = 4;
	private static final int JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE = 8;
	private static final int JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE = 4;
	private static final int JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE = 5;
	
	private static final int XSTREAM_INITIALIZATIONEXCEPTION_CLASS_EDITOR_NUMBER_DIFFERENCE = 9;
	private static final int XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE = 136;
	private static final int XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 17;
	private static final int XSTREAM_BIGDECIMALCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_BIGINTEGERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_BYTECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 15;
	private static final int XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 24;
	private static final int XSTREAM_DOUBLECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_FLOATCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_INTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_LONGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_SHORTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_STRINGBUFFERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 13;
	private static final int XSTREAM_URICONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 12;
	private static final int XSTREAM_URLCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 13;
	private static final int XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE = 18;
	private static final int XSTREAM_BITSETCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 17;
	private static final int XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 22;
	private static final int XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 20;
	private static final int XSTREAM_TOSTRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 13;
	private static final int XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 22;
	private static final int XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE = 22;
	private static final int XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE = 9;
	private static final int XSTREAM_IMMUTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 9;
	private static final int XSTREAM_NATIVEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 11;
	private static final int XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE = 16;
	private static final int XSTREAM_CLONEABLES_CLASS_EDITOR_NUMBER_DIFFERENCE = 13;
	private static final int XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE = 15;
	private static final int XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE = 17;
	private static final int XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE = 9;
	private static final int XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE = 18;
	private static final int XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE = 9;
	private static final int XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE = 18;
	private static final int XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE = 15;
	private static final int XSTREAM_ANNOTATIONCONFIGURATION_CLASS_EDITOR_NUMBER_DIFFERENCE = 9;
	private static final int XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE = 43;
	private static final int XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE = 10;
	private static final int XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE = 11;
		
	private static final int METHOD_BOUND_SIZE = 6;
	private static final int LINE_BOUND_SIZE = 7;
	
	public SuspiciousCode(){
		jsoupMethods = loadjsoupMethods();
		xstreamMethods = loadxstreamMethods();
		jsoupLines = loadjsoupLines();
		xstreamLines = loadxstreamLines();
	}
	
	private static Map<String,int[]> loadjsoupMethods(){
		Map<String,int[]> methods = new HashMap<String,int[]>();
		int bounds[] = new int[METHOD_BOUND_SIZE];
		String methodName = "";
		
		methodName = "Element.nextElementSibling()";
		bounds[0] = 503;
		bounds[1] = 521;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 512;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.equals(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1185;
		bounds[1] = 1193;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1185;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.equals(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 160;
		bounds[1] = 173;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 166;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.equals(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 181;
		bounds[1] = 197;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 181;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.indexInList(Element,Index<E>)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 568;
		bounds[1] = 579;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 568;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.equals(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 177;
		bounds[1] = 185;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 177;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.equals(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 591;
		bounds[1] = 599;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 591;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.previousElementSibling()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 523;
		bounds[1] = 537;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 528;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.children()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 175;
		bounds[1] = 192;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 184;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementById(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 595;
		bounds[1] = 612;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 604;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.elementSiblingIndex()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 549;
		bounds[1] = 557;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 554;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "HtmlTreeBuilderState$7.process(Token,HtmlTreeBuilder)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 245;
		bounds[1] = 752;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 245;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
			
		methodName = "Evaluator$2.matches(Element,Element)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 65;
		bounds[1] = 67;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 65;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		//new methods beyond the best ranked ones
		
		methodName = "Element.Element(Tag,String,Attributes)";
		bounds[0] = 26;
		bounds[1] = 40;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 35;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.Element(Tag,String)";
		bounds[0] = 42;
		bounds[1] = 52;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 50;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
			
		methodName = "Element.nodeName()";
		bounds[0] = 54;
		bounds[1] = 57;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 55;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.tagName()";
		bounds[0] = 59;
		bounds[1] = 66;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 64;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.tagName(String)";
		bounds[0] = 68;
		bounds[1] = 79;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 75;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.tag()";
		bounds[0] = 81;
		bounds[1] = 88;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 86;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.isBlock()";
		bounds[0] = 90;
		bounds[1] = 98;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 96;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.id()";
		bounds[0] = 100;
		bounds[1] = 107;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 105;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.attr(String,String)";
		bounds[0] = 109;
		bounds[1] = 118;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 115;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.dataset()";
		bounds[0] = 120;
		bounds[1] = 135;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 132;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.parent()";
		bounds[0] = 137;
		bounds[1] = 140;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 138;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.parents()";
		bounds[0] = 142;
		bounds[1] = 150;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 146;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.accumulateParents(Element,Elements)";
		bounds[0] = 152;
		bounds[1] = 158;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 152;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.child(int)";
		bounds[0] = 160;
		bounds[1] = 173;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 171;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.textNodes()";
		bounds[0] = 194;
		bounds[1] = 217;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 210;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.dataNodes()";
		bounds[0] = 219;
		bounds[1] = 235;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 228;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.select(String)";
		bounds[0] = 237;
		bounds[1] = 259;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 257;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.appendChild(Node)";
		bounds[0] = 261;
		bounds[1] = 275;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 267;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.prependChild(Node)";
		bounds[0] = 277;
		bounds[1] = 288;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 283;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.insertChildren(int,Collection<? extends Node>)";
		bounds[0] = 291;
		bounds[1] = 310;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 300;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.appendElement(String)";
		bounds[0] = 312;
		bounds[1] = 323;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 319;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.prependElement(String)";
		bounds[0] = 325;
		bounds[1] = 336;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 332;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.appendText(String)";
		bounds[0] = 338;
		bounds[1] = 348;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 344;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.prependText(String)";
		bounds[0] = 350;
		bounds[1] = 360;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 356;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.append(String)";
		bounds[0] = 362;
		bounds[1] = 374;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 368;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.prepend(String)";
		bounds[0] = 376;
		bounds[1] = 388;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 382;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.before(String)";
		bounds[0] = 390;
		bounds[1] = 400;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 398;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.before(Node)";
		bounds[0] = 402;
		bounds[1] = 411;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 409;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.after(String)";
		bounds[0] = 413;
		bounds[1] = 423;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 421;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.after(Node)";
		bounds[0] = 425;
		bounds[1] = 434;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 432;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.empty()";
		bounds[0] = 436;
		bounds[1] = 443;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 440;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.cssSelector()";
		bounds[0] = 456;
		bounds[1] = 484;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 466;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.siblingElements()";
		bounds[0] = 486;
		bounds[1] = 501;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 491;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.firstElementSibling()";
		bounds[0] = 539;
		bounds[1] = 547;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 543;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.lastElementSibling()";
		bounds[0] = 559;
		bounds[1] = 566;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 563;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByTag(String)";
		bounds[0] = 583;
		bounds[1] = 593;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 588;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByClass(String)";
		bounds[0] = 614;
		bounds[1] = 629;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 625;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByAttribute(String)";
		bounds[0] = 631;
		bounds[1] = 642;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 637;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByAttributeStarting(String)";
		bounds[0] = 644;
		bounds[1] = 655;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 650;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByAttributeValue(String,String)";
		bounds[0] = 657;
		bounds[1] = 666;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 664;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByAttributeValueNot(String,String)";
		bounds[0] = 668;
		bounds[1] = 677;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 675;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByAttributeValueStarting(String,String)";
		bounds[0] = 679;
		bounds[1] = 688;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 686;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByAttributeValueEnding(String,String)";
		bounds[0] = 690;
		bounds[1] = 699;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 697;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByAttributeValueContaining(String,String)";
		bounds[0] = 701;
		bounds[1] = 710;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 708;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByAttributeValueMatching(String,Pattern)";
		bounds[0] = 712;
		bounds[1] = 721;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 718;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByAttributeValueMatching(String,String)";
		bounds[0] = 723;
		bounds[1] = 737;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 729;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByIndexLessThan(int)";
		bounds[0] = 739;
		bounds[1] = 746;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 744;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByIndexGreaterThan(int)";
		bounds[0] = 748;
		bounds[1] = 755;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 753;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsByIndexEquals(int)";
		bounds[0] = 757;
		bounds[1] = 764;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 762;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsContainingText(String)";
		bounds[0] = 766;
		bounds[1] = 775;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 773;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsContainingOwnText(String)";
		bounds[0] = 777;
		bounds[1] = 786;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 784;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsMatchingText(Pattern)";
		bounds[0] = 788;
		bounds[1] = 796;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 794;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsMatchingText(String)";
		bounds[0] = 798;
		bounds[1] = 812;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 810;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsMatchingOwnText(Pattern)";
		bounds[0] = 814;
		bounds[1] = 822;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 820;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getElementsMatchingOwnText(String)";
		bounds[0] = 824;
		bounds[1] = 838;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 830;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.getAllElements()";
		bounds[0] = 840;
		bounds[1] = 847;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 845;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.text()";
		bounds[0] = 849;
		bounds[1] = 878;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 858;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.ownText()";
		bounds[0] = 880;
		bounds[1] = 895;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 891;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.ownText(StringBuilder)";
		bounds[0] = 897;
		bounds[1] = 906;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 897;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.appendNormalisedText(StringBuilder,TextNode)";
		bounds[0] = 908;
		bounds[1] = 915;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 908;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.appendWhitespaceIfBr(Element,StringBuilder)";
		bounds[0] = 917;
		bounds[1] = 920;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 917;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.preserveWhitespace(Node)";
		bounds[0] = 922;
		bounds[1] = 930;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 922;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.text(String)";
		bounds[0] = 932;
		bounds[1] = 945;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 937;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.hasText()";
		bounds[0] = 947;
		bounds[1] = 964;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 951;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.data()";
		bounds[0] = 966;
		bounds[1] = 976;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 972;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.className()";
		bounds[0] = 988;
		bounds[1] = 995;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 993;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.classNames()";
		bounds[0] = 997;
		bounds[1] = 1009;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1003;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.classNames(Set<String>)";
		bounds[0] = 1011;
		bounds[1] = 1020;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1016;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.hasClass(String)";
		bounds[0] = 1022;
		bounds[1] = 1047;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1035;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.addClass(String)";
		bounds[0] = 1049;
		bounds[1] = 1062;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1054;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.removeClass(String)";
		bounds[0] = 1064;
		bounds[1] = 1077;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1069;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.toggleClass(String)";
		bounds[0] = 1079;
		bounds[1] = 1095;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1084;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.val()";
		bounds[0] = 1097;
		bounds[1] = 1106;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1069;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.val(String)";
		bounds[0] = 1108;
		bounds[1] = 1119;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1113;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.outerHtmlHead(StringBuilder,int,Document.OutputSettings)";
		bounds[0] = 1121;
		bounds[1] = 1138;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1121;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.outerHtmlTail(StringBuilder,int,Document.OutputSettings)";
		bounds[0] = 1140;
		bounds[1] = 1148;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1140;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.html()";
		bounds[0] = 1150;
		bounds[1] = 1161;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1157;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.html(StringBuilder)";
		bounds[0] = 1163;
		bounds[1] = 1166;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1163;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.html(String)";
		bounds[0] = 1168;
		bounds[1] = 1178;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1174;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.toString()";
		bounds[0] = 1180;
		bounds[1] = 1182;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1180;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.hashCode()";
		bounds[0] = 1196;
		bounds[1] = 1200;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1196;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Element.toString()";
		bounds[0] = 1203;
		bounds[1] = 1205;
		bounds[2] = bounds[0] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1203;
		bounds[5] = bounds[4] - JSOUP_ELEMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		//Attributes
		
		methodName = "Attributes.get(String)";
		bounds[0] = 26;
		bounds[1] = 40;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 32;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
	
		methodName = "Attributes.put(String,String)";
		bounds[0] = 42;
		bounds[1] = 50;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 47;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.put(Attribute)";
		bounds[0] = 52;
		bounds[1] = 61;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 56;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.remove(String)";
		bounds[0] = 63;
		bounds[1] = 72;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 67;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.hasKey(String)";
		bounds[0] = 74;
		bounds[1] = 81;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 79;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.size()";
		bounds[0] = 83;
		bounds[1] = 91;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 87;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.addAll(Attributes)";
		bounds[0] = 93;
		bounds[1] = 103;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 97;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.iterator()";
		bounds[0] = 105;
		bounds[1] = 107;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 105;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.asList()";
		bounds[0] = 109;
		bounds[1] = 123;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 114;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.dataset()";
		bounds[0] = 125;
		bounds[1] = 132;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 130;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.html()";
		bounds[0] = 134;
		bounds[1] = 142;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 138;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.html(StringBuilder,Document.OutputSettings)";
		bounds[0] = 144;
		bounds[1] = 153;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 144;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.toString()";
		bounds[0] = 156;
		bounds[1] = 158;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 156;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.hashCode()";
		bounds[0] = 175;
		bounds[1] = 182;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 180;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.clone()";
		bounds[0] = 185;
		bounds[1] = 199;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 185;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes$1.Dataset()";
		bounds[0] = 203;
		bounds[1] = 206;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 203;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes$1.entrySet()";
		bounds[0] = 209;
		bounds[1] = 211;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 209;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes$1.put()";
		bounds[0] = 214;
		bounds[1] = 220;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 214;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes$1.iterator()";
		bounds[0] = 225;
		bounds[1] = 227;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 225;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes$1.size()";
		bounds[0] = 230;
		bounds[1] = 235;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 230;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes$1.hasNext()";
		bounds[0] = 242;
		bounds[1] = 248;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 242;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes$1.next()";
		bounds[0] = 250;
		bounds[1] = 252;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 250;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);

		methodName = "Attributes$1.remove()";
		bounds[0] = 254;
		bounds[1] = 256;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 254;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Attributes.dataKey(String)";
		bounds[0] = 260;
		bounds[1] = 262;
		bounds[2] = bounds[0] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 260;
		bounds[5] = bounds[4] - JSOUP_ATTRIBUTES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		//Tag
		
		methodName = "Tag.getName()";
		bounds[0] = 31;
		bounds[1] = 38;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 36;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.valueOf(String)";
		bounds[0] = 40;
		bounds[1] = 66;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 49;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.isBlock()";
		bounds[0] = 68;
		bounds[1] = 75;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 73;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.formatAsBlock()";
		bounds[0] = 77;
		bounds[1] = 84;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 82;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.canContainBlock()";
		bounds[0] = 86;
		bounds[1] = 93;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 91;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.isInline()";
		bounds[0] = 95;
		bounds[1] = 102;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 100;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.isData()";
		bounds[0] = 104;
		bounds[1] = 111;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 109;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.isEmpty()";
		bounds[0] = 113;
		bounds[1] = 120;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 118;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.isSelfClosing()";
		bounds[0] = 122;
		bounds[1] = 129;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 127;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.isKnownTag()";
		bounds[0] = 131;
		bounds[1] = 138;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 136;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.isKnownTag(String)";
		bounds[0] = 140;
		bounds[1] = 148;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 146;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.preserveWhitespace()";
		bounds[0] = 150;
		bounds[1] = 157;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 155;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.isFormListed()";
		bounds[0] = 159;
		bounds[1] = 165;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 163;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.isFormSubmittable()";
		bounds[0] = 167;
		bounds[1] = 173;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 171;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.setSelfClosing()";
		bounds[0] = 175;
		bounds[1] = 178;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 175;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.hashCode()";
		bounds[0] = 200;
		bounds[1] = 212;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 200;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.toString()";
		bounds[0] = 215;
		bounds[1] = 217;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 215;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Tag.register(Tag)";
		bounds[0] = 305;
		bounds[1] = 307;
		bounds[2] = bounds[0] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 305;
		bounds[5] = bounds[4] - JSOUP_TAG_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		//Node
		methodName = "Node.Node(String,Attributes)";
		bounds[0] = 27;
		bounds[1] = 39;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 32;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.Node(String)";
		bounds[0] = 41;
		bounds[1] = 43;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 41;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.Node()";
		bounds[0] = 45;
		bounds[1] = 51;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 48;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.nodeName()";
		bounds[0] = 53;
		bounds[1] = 57;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 57;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.attr(String)";
		bounds[0] = 59;
		bounds[1] = 82;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 74;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.attributes()";
		bounds[0] = 84;
		bounds[1] = 90;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 88;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.attr(String,String)";
		bounds[0] = 92;
		bounds[1] = 101;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 98;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.hasAttr(String)";
		bounds[0] = 103;
		bounds[1] = 117;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 108;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.removeAttr(String)";
		bounds[0] = 119;
		bounds[1] = 128;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 124;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.baseUri()";
		bounds[0] = 130;
		bounds[1] = 136;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 134;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.setBaseUri(String)";
		bounds[0] = 138;
		bounds[1] = 153;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 142;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.absUrl(String)";
		bounds[0] = 155;
		bounds[1] = 203;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 178;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.childNode(int)";
		bounds[0] = 205;
		bounds[1] = 212;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 210;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.childNodes()";
		bounds[0] = 214;
		bounds[1] = 221;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 219;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.childNodesCopy()";
		bounds[0] = 223;
		bounds[1] = 234;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 228;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.childNodeSize()";
		bounds[0] = 236;
		bounds[1] = 242;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 240;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.childNodesAsArray()";
		bounds[0] = 244;
		bounds[1] = 246;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 244;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.parent()";
		bounds[0] = 248;
		bounds[1] = 254;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 252;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.parentNode()";
		bounds[0] = 256;
		bounds[1] = 262;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 260;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.ownerDocument()";
		bounds[0] = 264;
		bounds[1] = 275;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 268;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.remove()";
		bounds[0] = 277;
		bounds[1] = 283;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 280;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.before(String)";
		bounds[0] = 285;
		bounds[1] = 294;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 291;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.before(Node)";
		bounds[0] = 296;
		bounds[1] = 308;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 302;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.after(String)";
		bounds[0] = 310;
		bounds[1] = 319;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 316;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.after(Node)";
		bounds[0] = 321;
		bounds[1] = 333;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 327;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.addSiblingHtml(int,String)";
		bounds[0] = 335;
		bounds[1] = 342;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 335;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.wrap(String)";
		bounds[0] = 344;
		bounds[1] = 372;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 349;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.unwrap()";
		bounds[0] = 374;
		bounds[1] = 397;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 389;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.getDeepChild(Element)";
		bounds[0] = 399;
		bounds[1] = 405;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 399;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.replaceWith(Node)";
		bounds[0] = 407;
		bounds[1] = 415;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 411;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.setParentNode(Node)";
		bounds[0] = 417;
		bounds[1] = 421;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 417;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.replaceChild(Node,Node)";
		bounds[0] = 423;
		bounds[1] = 434;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 423;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.removeChild(Node)";
		bounds[0] = 436;
		bounds[1] = 442;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 436;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.addChildren(Node)";
		bounds[0] = 444;
		bounds[1] = 451;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 444;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.addChildren(int,Node)";
		bounds[0] = 453;
		bounds[1] = 461;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 453;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.reparentChild(Node)";
		bounds[0] = 463;
		bounds[1] = 467;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 463;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.reindexChildren(int)";
		bounds[0] = 469;
		bounds[1] = 473;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 469;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.siblingNodes()";
		bounds[0] = 475;
		bounds[1] = 490;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 480;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.nextSibling()";
		bounds[0] = 492;
		bounds[1] = 506;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 496;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.previousSibling()";
		bounds[0] = 508;
		bounds[1] = 520;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 512;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.siblingIndex()";
		bounds[0] = 522;
		bounds[1] = 530;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 528;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.setSiblingIndex(int)";
		bounds[0] = 532;
		bounds[1] = 534;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 532;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.traverse(NodeVisitor)";
		bounds[0] = 536;
		bounds[1] = 546;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 541;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.outerHtml()";
		bounds[0] = 548;
		bounds[1] = 556;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 552;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.outerHtml(StringBuilder)";
		bounds[0] = 558;
		bounds[1] = 560;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 558;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.getOutputSettings()";
		bounds[0] = 562;
		bounds[1] = 565;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 563;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.outerHtmlHead(StringBuilder,int,Document.OutputSettings)";
		bounds[0] = 567;
		bounds[1] = 571;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 571;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.outerHtmlTail(StringBuilder,int,Document.OutputSettings)";
		bounds[0] = 573;
		bounds[1] = 573;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 573;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.toString()";
		bounds[0] = 576;
		bounds[1] = 578;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 576;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.indent(StringBuilder,int,Document.OutputSettings)";
		bounds[0] = 580;
		bounds[1] = 582;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 580;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.hashCode()";
		bounds[0] = 601;
		bounds[1] = 613;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 609;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.clone()";
		bounds[0] = 615;
		bounds[1] = 642;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 624;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node.doClone(Node)";
		bounds[0] = 644;
		bounds[1] = 667;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 648;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node$1.OuterHtmlVisitor(StringBuilder,Document.OutputSettings)";
		bounds[0] = 673;
		bounds[1] = 676;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 673;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node$1.head(Node,int)";
		bounds[0] = 678;
		bounds[1] = 680;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 678;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Node$1.tail(Node,int)";
		bounds[0] = 682;
		bounds[1] = 685;
		bounds[2] = bounds[0] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 682;
		bounds[5] = bounds[4] - JSOUP_NODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		

		//TextNode
		
		methodName = "TextNode.TextNode(String,String)";
		bounds[0] = 19;
		bounds[1] = 29;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 26;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.nodeName()";
		bounds[0] = 31;
		bounds[1] = 33;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 31;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.text()";
		bounds[0] = 35;
		bounds[1] = 42;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 40;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.text(String)";
		bounds[0] = 44;
		bounds[1] = 54;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 49;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.getWholeText()";
		bounds[0] = 56;
		bounds[1] = 62;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 60;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.isBlank()";
		bounds[0] = 64;
		bounds[1] = 70;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 68;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.splitText(int)";
		bounds[0] = 72;
		bounds[1] = 90;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 78;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.outerHtmlHead(StringBuilder,int,Document.OutputSettings)";
		bounds[0] = 92;
		bounds[1] = 99;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 92;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.outerHtmlTail(StringBuilder,int,Document.OutputSettings)";
		bounds[0] = 101;
		bounds[1] = 101;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 101;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.toString()";
		bounds[0] = 104;
		bounds[1] = 106;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 104;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.createFromEncoded(String,String)";
		bounds[0] = 108;
		bounds[1] = 117;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 114;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.normaliseWhitespace(String)";
		bounds[0] = 119;
		bounds[1] = 122;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 119;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.stripLeadingWhitespace(String)";
		bounds[0] = 124;
		bounds[1] = 126;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 124;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.lastCharIsWhitespace(StringBuilder)";
		bounds[0] = 128;
		bounds[1] = 130;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 128;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.ensureAttributes()";
		bounds[0] = 132;
		bounds[1] = 138;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 133;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.attr(String)";
		bounds[0] = 141;
		bounds[1] = 144;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 141;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.attributes()";
		bounds[0] = 147;
		bounds[1] = 150;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 147;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.attr(String,String)";
		bounds[0] = 153;
		bounds[1] = 156;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 153;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.hasAttr(String)";
		bounds[0] = 159;
		bounds[1] = 162;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 159;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.removeAttr(String)";
		bounds[0] = 165;
		bounds[1] = 168;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 165;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.absUrl(String)";
		bounds[0] = 171;
		bounds[1] = 174;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 171;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TextNode.hashCode()";
		bounds[0] = 188;
		bounds[1] = 192;
		bounds[2] = bounds[0] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 188;
		bounds[5] = bounds[4] - JSOUP_TEXTNODE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		
		//HtmlTreeBuilderState
		
		methodName = "HtmlTreeBuilderState$1.process(Token,HtmlTreeBuilder)";
		bounds[0] = 13;
		bounds[1] = 33;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 13;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$2.process(Token,HtmlTreeBuilder)";
		bounds[0] = 36;
		bounds[1] = 56;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 36;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$2.anythingElse(Token,HtmlTreeBuilder)";
		bounds[0] = 58;
		bounds[1] = 62;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 58;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$3.process(Token,HtmlTreeBuilder)";
		bounds[0] = 65;
		bounds[1] = 90;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 65;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$4.process(Token,HtmlTreeBuilder)";
		bounds[0] = 93;
		bounds[1] = 157;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 93;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$4.anythingElse(Token,HtmlTreeBuilder)";
		bounds[0] = 159;
		bounds[1] = 162;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 159;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$5.process(Token,HtmlTreeBuilder)";
		bounds[0] = 165;
		bounds[1] = 185;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 165;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$5.anythingElse(Token,HtmlTreeBuilder)";
		bounds[0] = 187;
		bounds[1] = 191;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 187;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$6.process(Token,HtmlTreeBuilder)";
		bounds[0] = 194;
		bounds[1] = 236;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 194;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$6.anythingElse(Token,HtmlTreeBuilder)";
		bounds[0] = 238;
		bounds[1] = 242;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 238;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "HtmlTreeBuilderState$7.anyOtherEndTag(Token,HtmlTreeBuilder)";
		bounds[0] = 754;
		bounds[1] = 773;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 754;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$8.process(Token,HtmlTreeBuilder)";
		bounds[0] = 777;
		bounds[1] = 792;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 777;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$9.process(Token,HtmlTreeBuilder)";
		bounds[0] = 795;
		bounds[1] = 879;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 795;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$9.anythingElse(Token,HtmlTreeBuilder)";
		bounds[0] = 881;
		bounds[1] = 892;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 881;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "HtmlTreeBuilderState$10.process(Token,HtmlTreeBuilder)";
		bounds[0] = 895;
		bounds[1] = 929;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 895;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$11.process(Token,HtmlTreeBuilder)";
		bounds[0] = 932;
		bounds[1] = 964;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 932;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$12.process(Token,HtmlTreeBuilder)";
		bounds[0] = 967;
		bounds[1] = 1012;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 967;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$12.anythingElse(Token,HtmlTreeBuilder)";
		bounds[0] = 1014;
		bounds[1] = 1019;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1014;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$13.process(Token,HtmlTreeBuilder)";
		bounds[0] = 1022;
		bounds[1] = 1064;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1022;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$13.exitTableBody(Token,HtmlTreeBuilder)";
		bounds[0] = 1066;
		bounds[1] = 1075;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1066;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$13.anythingElse(Token,HtmlTreeBuilder)";
		bounds[0] = 1077;
		bounds[1] = 1079;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1077;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$14.process(Token,HtmlTreeBuilder)";
		bounds[0] = 1082;
		bounds[1] = 1128;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1082;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$14.anythingElse(Token,HtmlTreeBuilder)";
		bounds[0] = 1130;
		bounds[1] = 1132;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1130;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$14.handleMissingTr(Token,HtmlTreeBuilder)";
		bounds[0] = 1134;
		bounds[1] = 1140;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1134;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$15.process(Token,HtmlTreeBuilder)";
		bounds[0] = 1143;
		bounds[1] = 1186;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1143;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$15.anythingElse(Token,HtmlTreeBuilder)";
		bounds[0] = 1188;
		bounds[1] = 1190;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1188;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$15.closeCell(HtmlTreeBuilder)";
		bounds[0] = 1192;
		bounds[1] = 1197;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1192;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$16.process(Token,HtmlTreeBuilder)";
		bounds[0] = 1200;
		bounds[1] = 1280;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1200;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$16.anythingElse(Token,HtmlTreeBuilder)";
		bounds[0] = 1282;
		bounds[1] = 1285;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1282;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$17.process(Token,HtmlTreeBuilder)";
		bounds[0] = 1288;
		bounds[1] = 1303;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1288;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$18.process(Token,HtmlTreeBuilder)";
		bounds[0] = 1306;
		bounds[1] = 1331;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1306;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$19.process(Token,HtmlTreeBuilder)";
		bounds[0] = 1334;
		bounds[1] = 1377;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1334;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$20.process(Token,HtmlTreeBuilder)";
		bounds[0] = 1380;
		bounds[1] = 1401;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1380;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$21.process(Token,HtmlTreeBuilder)";
		bounds[0] = 1404;
		bounds[1] = 1417;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1404;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$22.process(Token,HtmlTreeBuilder)";
		bounds[0] = 1420;
		bounds[1] = 1434;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1420;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		methodName = "HtmlTreeBuilderState$23.process(Token,HtmlTreeBuilder)";
		bounds[0] = 1437;
		bounds[1] = 1440;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1437;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "HtmlTreeBuilderState.process(Token,HtmlTreeBuilder)";
		bounds[0] = 1445;
		bounds[1] = 1445;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1445;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "HtmlTreeBuilderState.isWhitespace(Token)";
		bounds[0] = 1447;
		bounds[1] = 1453;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1447;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "HtmlTreeBuilderState.isWhitespace(String)";
		bounds[0] = 1455;
		bounds[1] = 1463;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1455;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "HtmlTreeBuilderState.handleRcData(Token.StartTag,HtmlTreeBuilder)";
		bounds[0] = 1465;
		bounds[1] = 1470;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1465;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "HtmlTreeBuilderState.handleRawtext(Token.StartTag,HtmlTreeBuilder)";
		bounds[0] = 1472;
		bounds[1] = 1477;
		bounds[2] = bounds[0] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1472;
		bounds[5] = bounds[4] - JSOUP_HTMLTREEBUILDERSTATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		
		//Evaluator
		
		methodName = "Evaluator.Evaluator()";
		bounds[0] = 20;
		bounds[1] = 21;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 20;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator.matches(Element,Element)";
		bounds[0] = 23;
		bounds[1] = 31;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 31;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$1.Tag(String)";
		bounds[0] = 39;
		bounds[1] = 41;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 39;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$1.matches(Element,Element)";
		bounds[0] = 44;
		bounds[1] = 46;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 44;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$1.toString()";
		bounds[0] = 49;
		bounds[1] = 51;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 49;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$2.Id(String)";
		bounds[0] = 60;
		bounds[1] = 62;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 60;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$2.toString()";
		bounds[0] = 70;
		bounds[1] = 72;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 70;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$3.Class(String)";
		bounds[0] = 82;
		bounds[1] = 84;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 82;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$3.matches(Element,Element)";
		bounds[0] = 87;
		bounds[1] = 89;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 87;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$3.toString()";
		bounds[0] = 92;
		bounds[1] = 94;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 92;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$4.Attribute(String)";
		bounds[0] = 104;
		bounds[1] = 106;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 104;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$4.matches(Element,Element)";
		bounds[0] = 109;
		bounds[1] = 111;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 109;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$4.toString()";
		bounds[0] = 114;
		bounds[1] = 116;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 114;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$5.AttributeStarting(String)";
		bounds[0] = 126;
		bounds[1] = 128;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 126;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$5.matches(Element,Element)";
		bounds[0] = 131;
		bounds[1] = 138;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 131;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$5.toString()";
		bounds[0] = 141;
		bounds[1] = 143;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 141;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$6.AttributeWithValue(String,String)";
		bounds[0] = 151;
		bounds[1] = 153;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 151;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$6.matches(Element,Element)";
		bounds[0] = 156;
		bounds[1] = 158;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 156;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$6.toString()";
		bounds[0] = 161;
		bounds[1] = 163;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 161;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$7.AttributeWithValueNot(String,String)";
		bounds[0] = 171;
		bounds[1] = 173;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 171;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$7.matches(Element,Element)";
		bounds[0] = 176;
		bounds[1] = 178;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 176;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$7.toString()";
		bounds[0] = 181;
		bounds[1] = 183;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 181;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$8.AttributeWithValueStarting(String,String)";
		bounds[0] = 191;
		bounds[1] = 193;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 191;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$8.matches(Element,Element)";
		bounds[0] = 196;
		bounds[1] = 198;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 196;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$8.toString()";
		bounds[0] = 201;
		bounds[1] = 203;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 201;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$9.AttributeWithValueEnding(String,String)";
		bounds[0] = 211;
		bounds[1] = 213;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 211;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$9.matches(Element,Element)";
		bounds[0] = 216;
		bounds[1] = 218;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 216;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$9.toString()";
		bounds[0] = 221;
		bounds[1] = 223;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 221;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$10.AttributeWithValueContaining(String,String)";
		bounds[0] = 231;
		bounds[1] = 233;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 231;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$10.matches(Element,Element)";
		bounds[0] = 236;
		bounds[1] = 238;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 236;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$10.toString()";
		bounds[0] = 241;
		bounds[1] = 243;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 241;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$11.AttributeWithValueMatching(String,Pattern)";
		bounds[0] = 254;
		bounds[1] = 257;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 254;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$11.matches(Element,Element)";
		bounds[0] = 260;
		bounds[1] = 262;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 260;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$11.toString()";
		bounds[0] = 265;
		bounds[1] = 267;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 265;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$12.AttributeKeyPair(String,String)";
		bounds[0] = 278;
		bounds[1] = 287;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 278;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$13.matches(Element,Element)";
		bounds[0] = 296;
		bounds[1] = 298;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 296;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$13.toString()";
		bounds[0] = 301;
		bounds[1] = 303;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 301;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$14.IndexLessThan(int)";
		bounds[0] = 310;
		bounds[1] = 312;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 310;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$14.matches(Element,Element)";
		bounds[0] = 315;
		bounds[1] = 317;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 315;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$14.toString()";
		bounds[0] = 320;
		bounds[1] = 322;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 320;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$15.IndexGreaterThan(int)";
		bounds[0] = 330;
		bounds[1] = 332;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 330;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$15.matches(Element,Element)";
		bounds[0] = 335;
		bounds[1] = 337;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 335;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$15.toString()";
		bounds[0] = 340;
		bounds[1] = 342;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 340;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$16.IndexEquals(int)";
		bounds[0] = 350;
		bounds[1] = 352;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 350;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$16.matches(Element,Element)";
		bounds[0] = 355;
		bounds[1] = 357;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 355;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$16.toString()";
		bounds[0] = 360;
		bounds[1] = 362;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 360;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$17.matches(Element,Element)";
		bounds[0] = 371;
		bounds[1] = 374;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 371;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$17.toString()";
		bounds[0] = 377;
		bounds[1] = 379;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 377;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$18.IsFirstOfType()";
		bounds[0] = 383;
		bounds[1] = 385;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 383;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$18.toString()";
		bounds[0] = 387;
		bounds[1] = 389;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 387;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$19.IsLastOfType()";
		bounds[0] = 393;
		bounds[1] = 395;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 393;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$19.toString()";
		bounds[0] = 397;
		bounds[1] = 399;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 397;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$20.CssNthEvaluator(int,int)";
		bounds[0] = 406;
		bounds[1] = 409;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 406;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$20.CssNthEvaluator(int)";
		bounds[0] = 410;
		bounds[1] = 412;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 410;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$20.matches(Element,Element)";
		bounds[0] = 415;
		bounds[1] = 423;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 415;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$20.toString()";
		bounds[0] = 426;
		bounds[1] = 432;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 426;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$20.getPseudoClass()";
		bounds[0] = 434;
		bounds[1] = 434;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 434;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$20.calculatePosition(Element,Element";
		bounds[0] = 435;
		bounds[1] = 435;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 435;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$21.IsNthChild(int,int)";
		bounds[0] = 446;
		bounds[1] = 448;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 446;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$21.calculatePosition(Element,Element)";
		bounds[0] = 450;
		bounds[1] = 452;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 450;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$21.getPseudoClass()";
		bounds[0] = 455;
		bounds[1] = 457;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 455;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$22.IsNthLastChild(int,int)";
		bounds[0] = 466;
		bounds[1] = 468;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 466;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$22.calculatePosition(Element,Element)";
		bounds[0] = 471;
		bounds[1] = 473;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 471;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$22.getPseudoClass()";
		bounds[0] = 476;
		bounds[1] = 478;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 476;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$23.IsNthOfType(int,int)";
		bounds[0] = 486;
		bounds[1] = 488;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 486;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$23.calculatePosition(Element,Element)";
		bounds[0] = 490;
		bounds[1] = 498;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 490;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$23.getPseudoClass()";
		bounds[0] = 501;
		bounds[1] = 503;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 501;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$24.IsNthLastOfType(int,int)";
		bounds[0] = 508;
		bounds[1] = 510;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 508;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$24.calculatePosition(Element,Element)";
		bounds[0] = 513;
		bounds[1] = 520;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 513;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$24.getPseudoClass()";
		bounds[0] = 523;
		bounds[1] = 525;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 523;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$25.matches(Element,Element)";
		bounds[0] = 533;
		bounds[1] = 536;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 533;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$25.toString()";
		bounds[0] = 539;
		bounds[1] = 541;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 539;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$26.matches(Element,Element)";
		bounds[0] = 551;
		bounds[1] = 554;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 551;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$26.toString()";
		bounds[0] = 556;
		bounds[1] = 558;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 556;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$27.matches(Element,Element)";
		bounds[0] = 563;
		bounds[1] = 566;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 563;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$27.toString()";
		bounds[0] = 568;
		bounds[1] = 570;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 568;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$28.matches(Element,Element)";
		bounds[0] = 575;
		bounds[1] = 585;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 575;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$28.toString()";
		bounds[0] = 587;
		bounds[1] = 589;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 587;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$29.matches(Element,Element)";
		bounds[0] = 594;
		bounds[1] = 601;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 594;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$29.toString()";
		bounds[0] = 603;
		bounds[1] = 605;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 603;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$30.IndexEvaluator(int)";
		bounds[0] = 616;
		bounds[1] = 618;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 616;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$31.ContainsText(String)";
		bounds[0] = 627;
		bounds[1] = 629;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 627;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$31.matches(Element,Element)";
		bounds[0] = 632;
		bounds[1] = 634;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 632;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$31.toString()";
		bounds[0] = 637;
		bounds[1] = 639;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 637;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$32.ContainsOwnText(String)";
		bounds[0] = 648;
		bounds[1] = 650;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 648;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$32.matches(Element,Element)";
		bounds[0] = 653;
		bounds[1] = 655;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 653;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$32.toString()";
		bounds[0] = 658;
		bounds[1] = 660;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 658;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$33.Matches(Pattern)";
		bounds[0] = 669;
		bounds[1] = 671;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 669;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$33.matches(Element,Element)";
		bounds[0] = 674;
		bounds[1] = 677;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 674;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$33.toString()";
		bounds[0] = 680;
		bounds[1] = 682;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 680;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$34.MatchesOwn(Pattern)";
		bounds[0] = 691;
		bounds[1] = 693;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 691;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$34.matches(Element,Element)";
		bounds[0] = 696;
		bounds[1] = 699;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 696;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Evaluator$34.toString()";
		bounds[0] = 702;
		bounds[1] = 704;
		bounds[2] = bounds[0] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 702;
		bounds[5] = bounds[4] - JSOUP_EVALUATOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
				
		//Jsoup
		
		methodName = "Jsoup.parse(String,String)";
		bounds[0] = 22;
		bounds[1] = 32;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 30;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.parse(String,String,Parser)";
		bounds[0] = 34;
		bounds[1] = 46;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 44;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.parse(String)";
		bounds[0] = 48;
		bounds[1] = 59;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 57;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.connect(String)";
		bounds[0] = 61;
		bounds[1] = 74;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 72;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.parse(File,String,String)";
		bounds[0] = 76;
		bounds[1] = 89;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 87;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.parse(File,String)";
		bounds[0] = 91;
		bounds[1] = 104;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 102;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.parse(InputStream,String,String)";
		bounds[0] = 106;
		bounds[1] = 119;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 117;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.parse(InputStream,String,String,Parser)";
		bounds[0] = 121;
		bounds[1] = 136;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 121;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.parseBodyFragment(String,String)";
		bounds[0] = 138;
		bounds[1] = 149;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 147;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.parseBodyFragment(String)";
		bounds[0] = 151;
		bounds[1] = 161;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 159;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.parse(URL,int)";
		bounds[0] = 163;
		bounds[1] = 184;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 180;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.clean(String,String,Whitelist)";
		bounds[0] = 186;
		bounds[1] = 202;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 197;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.clean(String,Whitelist)";
		bounds[0] = 204;
		bounds[1] = 216;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 214;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.clean(String,String,Whitelist,Document.OutputSettings)";
		bounds[0] = 218;
		bounds[1] = 236;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 230;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Jsoup.isValid(String,Whitelist)";
		bounds[0] = 238;
		bounds[1] = 250;
		bounds[2] = bounds[0] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 246;
		bounds[5] = bounds[4] - JSOUP_JSOUP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		//Validate
		
		methodName = "Validate.notNull(Object)";
		bounds[0] = 10;
		bounds[1] = 17;
		bounds[2] = bounds[0] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 14;
		bounds[5] = bounds[4] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Validate.notNull(Object,String)";
		bounds[0] = 19;
		bounds[1] = 27;
		bounds[2] = bounds[0] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 24;
		bounds[5] = bounds[4] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Validate.isTrue(boolean)";
		bounds[0] = 29;
		bounds[1] = 36;
		bounds[2] = bounds[0] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 33;
		bounds[5] = bounds[4] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Validate.isTrue(boolean,String)";
		bounds[0] = 38;
		bounds[1] = 46;
		bounds[2] = bounds[0] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 43;
		bounds[5] = bounds[4] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Validate.isFalse(boolean)";
		bounds[0] = 48;
		bounds[1] = 55;
		bounds[2] = bounds[0] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 52;
		bounds[5] = bounds[4] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Validate.isFalse(boolean,String)";
		bounds[0] = 57;
		bounds[1] = 65;
		bounds[2] = bounds[0] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 62;
		bounds[5] = bounds[4] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Validate.noNullElements(Object[])";
		bounds[0] = 67;
		bounds[1] = 73;
		bounds[2] = bounds[0] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 71;
		bounds[5] = bounds[4] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Validate.noNullElements(Object[],String)";
		bounds[0] = 75;
		bounds[1] = 84;
		bounds[2] = bounds[0] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 80;
		bounds[5] = bounds[4] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Validate.notEmpty(String)";
		bounds[0] = 86;
		bounds[1] = 93;
		bounds[2] = bounds[0] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 90;
		bounds[5] = bounds[4] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Validate.notEmpty(String,String)";
		bounds[0] = 95;
		bounds[1] = 103;
		bounds[2] = bounds[0] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 100;
		bounds[5] = bounds[4] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Validate.fail(String)";
		bounds[0] = 105;
		bounds[1] = 111;
		bounds[2] = bounds[0] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 109;
		bounds[5] = bounds[4] - JSOUP_VALIDATE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		
		//Document
		
		methodName = "Document.Document(String)";
		bounds[0] = 23;
		bounds[1] = 32;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 29;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.createShell(String)";
		bounds[0] = 34;
		bounds[1] = 48;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 39;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.location()";
		bounds[0] = 50;
		bounds[1] = 57;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 55;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.head()";
		bounds[0] = 59;
		bounds[1] = 65;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 63;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.body()";
		bounds[0] = 67;
		bounds[1] = 73;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 71;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.title()";
		bounds[0] = 75;
		bounds[1] = 83;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 79;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.title(String)";
		bounds[0] = 85;
		bounds[1] = 98;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 90;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.createElement(String)";
		bounds[0] = 100;
		bounds[1] = 107;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 105;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.normalise()";
		bounds[0] = 109;
		bounds[1] = 135;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 114;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.normaliseTextNodes(Element)";
		bounds[0] = 137;
		bounds[1] = 154;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 138;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.normaliseStructure(String,Element)";
		bounds[0] = 156;
		bounds[1] = 176;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 157;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.findFirstElementByTagName(String,Node)";
		bounds[0] = 178;
		bounds[1] = 190;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 179;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.outerHtml()";
		bounds[0] = 193;
		bounds[1] = 195;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 193;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.text(String)";
		bounds[0] = 197;
		bounds[1] = 206;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 203;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.nodeName()";
		bounds[0] = 209;
		bounds[1] = 211;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 209;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.charset(Charset)";
		bounds[0] = 213;
		bounds[1] = 241;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 237;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.charset()";
		bounds[0] = 243;
		bounds[1] = 253;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 251;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.updateMetaCharsetElement(boolean)";
		bounds[0] = 255;
		bounds[1] = 270;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 268;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.updateMetaCharsetElement()";
		bounds[0] = 272;
		bounds[1] = 282;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 280;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.clone()";
		bounds[0] = 285;
		bounds[1] = 289;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 285;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.ensureMetaCharsetElement()";
		bounds[0] = 291;
		bounds[1] = 361;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 310;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.OutputSettings()";
		bounds[0] = 381;
		bounds[1] = 381;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 381;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.escapeMode()";
		bounds[0] = 383;
		bounds[1] = 393;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 391;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.escapeMode(Entities.EscapeMode)";
		bounds[0] = 395;
		bounds[1] = 404;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 401;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.charset()";
		bounds[0] = 406;
		bounds[1] = 416;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 414;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.charset(Charset)";
		bounds[0] = 418;
		bounds[1] = 427;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 423;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.charset(String)";
		bounds[0] = 429;
		bounds[1] = 437;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 434;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.encoder()";
		bounds[0] = 439;
		bounds[1] = 441;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 439;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.syntax()";
		bounds[0] = 443;
		bounds[1] = 449;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 447;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.syntax(Syntax)";
		bounds[0] = 451;
		bounds[1] = 460;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 457;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.prettyPrint()";
		bounds[0] = 462;
		bounds[1] = 469;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 467;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.prettyPrint(boolean)";
		bounds[0] = 471;
		bounds[1] = 479;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 476;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.outline()";
		bounds[0] = 481;
		bounds[1] = 488;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 486;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.outline(boolean)";
		bounds[0] = 490;
		bounds[1] = 498;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 495;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.indentAmount()";
		bounds[0] = 500;
		bounds[1] = 506;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 504;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.indentAmount(int)";
		bounds[0] = 508;
		bounds[1] = 517;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 513;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document$1.clone()";
		bounds[0] = 520;
		bounds[1] = 531;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 520;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.outputSettings()";
		bounds[0] = 534;
		bounds[1] = 540;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 538;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.outputSettings(OutputSettings)";
		bounds[0] = 542;
		bounds[1] = 551;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 547;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.quirksMode()";
		bounds[0] = 557;
		bounds[1] = 559;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 557;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Document.quirksMode(QuirksMode)";
		bounds[0] = 561;
		bounds[1] = 564;
		bounds[2] = bounds[0] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 561;
		bounds[5] = bounds[4] - JSOUP_DOCUMENT_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
				
		
		//Parser
		
		methodName = "Parser.Parser(TreeBuilder)";
		bounds[0] = 20;
		bounds[1] = 26;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 24;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.parseInput(String,String)";
		bounds[0] = 28;
		bounds[1] = 31;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 28;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.getTreeBuilder()";
		bounds[0] = 34;
		bounds[1] = 40;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 38;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.setTreeBuilder(TreeBuilder)";
		bounds[0] = 42;
		bounds[1] = 50;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 47;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.isTrackErrors()";
		bounds[0] = 52;
		bounds[1] = 58;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 56;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.setTrackErrors(int)";
		bounds[0] = 60;
		bounds[1] = 68;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 65;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.getErrors()";
		bounds[0] = 70;
		bounds[1] = 76;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 74;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.parse(String,String)";
		bounds[0] = 79;
		bounds[1] = 90;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 87;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.parseFragment(String,Element,String)";
		bounds[0] = 92;
		bounds[1] = 105;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 102;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.parseXmlFragment(String,String)";
		bounds[0] = 107;
		bounds[1] = 117;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 114;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.parseBodyFragment(String,String)";
		bounds[0] = 119;
		bounds[1] = 139;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 127;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.unescapeEntities(String,boolean)";
		bounds[0] = 141;
		bounds[1] = 150;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 147;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.parseBodyFragmentRelaxed(String,String)";
		bounds[0] = 152;
		bounds[1] = 161;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 159;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.htmlParser()";
		bounds[0] = 165;
		bounds[1] = 172;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 170;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Parser.xmlParser()";
		bounds[0] = 174;
		bounds[1] = 181;
		bounds[2] = bounds[0] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 179;
		bounds[5] = bounds[4] - JSOUP_PARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		
		//TreeBuilder
		
		methodName = "TreeBuilder.initialiseParse(String,String,ParseErrorList)";
		bounds[0] = 25;
		bounds[1] = 35;
		bounds[2] = bounds[0] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 25;
		bounds[5] = bounds[4] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TreeBuilder.parse(String,String)";
		bounds[0] = 37;
		bounds[1] = 39;
		bounds[2] = bounds[0] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 37;
		bounds[5] = bounds[4] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TreeBuilder.parse(String,String,ParseErrorList)";
		bounds[0] = 41;
		bounds[1] = 45;
		bounds[2] = bounds[0] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 41;
		bounds[5] = bounds[4] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TreeBuilder.runParser()";
		bounds[0] = 47;
		bounds[1] = 56;
		bounds[2] = bounds[0] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 47;
		bounds[5] = bounds[4] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TreeBuilder.process(Token)";
		bounds[0] = 58;
		bounds[1] = 58;
		bounds[2] = bounds[0] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 58;
		bounds[5] = bounds[4] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TreeBuilder.processStartTag(String)";
		bounds[0] = 60;
		bounds[1] = 62;
		bounds[2] = bounds[0] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 60;
		bounds[5] = bounds[4] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TreeBuilder.processStartTag(String,Attributes)";
		bounds[0] = 64;
		bounds[1] = 68;
		bounds[2] = bounds[0] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 64;
		bounds[5] = bounds[4] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TreeBuilder.processEndTag(String)";
		bounds[0] = 70;
		bounds[1] = 72;
		bounds[2] = bounds[0] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 70;
		bounds[5] = bounds[4] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "TreeBuilder.currentElement()";
		bounds[0] = 75;
		bounds[1] = 78;
		bounds[2] = bounds[0] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 75;
		bounds[5] = bounds[4] - JSOUP_TREEBUILDER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		
		//Collector
		
		methodName = "Collector.Collector()";
		bounds[0] = 13;
		bounds[1] = 14;
		bounds[2] = bounds[0] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 13;
		bounds[5] = bounds[4] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Collector.collect(Evaluator,Element)";
		bounds[0] = 16;
		bounds[1] = 26;
		bounds[2] = bounds[0] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 22;
		bounds[5] = bounds[4] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Collector$1.Accumulator(Element,Elements,Evaluator)";
		bounds[0] = 33;
		bounds[1] = 37;
		bounds[2] = bounds[0] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 33;
		bounds[5] = bounds[4] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Collector$1.head(Node,int)";
		bounds[0] = 39;
		bounds[1] = 45;
		bounds[2] = bounds[0] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 39;
		bounds[5] = bounds[4] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Collector$1.tail(Node,int)";
		bounds[0] = 47;
		bounds[1] = 49;
		bounds[2] = bounds[0] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 47;
		bounds[5] = bounds[4] - JSOUP_COLLECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		
		//Elements
		
		methodName = "Elements.Elements()";
		bounds[0] = 18;
		bounds[1] = 19;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 18;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.Elements(int)";
		bounds[0] = 21;
		bounds[1] = 23;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 21;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.Elements(Collection<Element>)";
		bounds[0] = 25;
		bounds[1] = 27;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 25;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.Elements(List<Element>)";
		bounds[0] = 29;
		bounds[1] = 31;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 29;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.Elements(Element)";
		bounds[0] = 33;
		bounds[1] = 35;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 33;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.clone()";
		bounds[0] = 37;
		bounds[1] = 49;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 42;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.attr(String)";
		bounds[0] = 52;
		bounds[1] = 65;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 59;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.hasAttr(String)";
		bounds[0] = 67;
		bounds[1] = 78;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 72;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.attr(String,String)";
		bounds[0] = 80;
		bounds[1] = 91;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 86;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.removeAttr(String)";
		bounds[0] = 93;
		bounds[1] = 103;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 93;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.addClass(String)";
		bounds[0] = 105;
		bounds[1] = 115;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 110;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.removeClass(String)";
		bounds[0] = 117;
		bounds[1] = 127;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 122;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.toggleClass(String)";
		bounds[0] = 129;
		bounds[1] = 139;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 134;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.hasClass(String)";
		bounds[0] = 141;
		bounds[1] = 152;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 146;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.val()";
		bounds[0] = 154;
		bounds[1] = 164;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 159;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.val(String)";
		bounds[0] = 166;
		bounds[1] = 175;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 171;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.text()";
		bounds[0] = 177;
		bounds[1] = 193;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 185;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.hasText()";
		bounds[0] = 195;
		bounds[1] = 201;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 195;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.html()";
		bounds[0] = 203;
		bounds[1] = 217;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 209;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.outerHtml()";
		bounds[0] = 219;
		bounds[1] = 233;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 225;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.toString()";
		bounds[0] = 235;
		bounds[1] = 244;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 242;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.tagName(String)";
		bounds[0] = 246;
		bounds[1] = 258;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 253;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.html(String)";
		bounds[0] = 260;
		bounds[1] = 271;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 266;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.prepend(String)";
		bounds[0] = 273;
		bounds[1] = 284;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 279;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.append(String)";
		bounds[0] = 286;
		bounds[1] = 297;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 292;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.before(String)";
		bounds[0] = 299;
		bounds[1] = 310;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 305;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.after(String)";
		bounds[0] = 312;
		bounds[1] = 323;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 318;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.wrap(String)";
		bounds[0] = 325;
		bounds[1] = 340;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 334;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.unwrap()";
		bounds[0] = 342;
		bounds[1] = 361;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 356;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.empty()";
		bounds[0] = 363;
		bounds[1] = 379;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 374;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.remove()";
		bounds[0] = 381;
		bounds[1] = 398;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 393;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.select(String)";
		bounds[0] = 402;
		bounds[1] = 409;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 407;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.not(String)";
		bounds[0] = 411;
		bounds[1] = 424;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 421;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.eq(int)";
		bounds[0] = 426;
		bounds[1] = 435;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 433;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.is(String)";
		bounds[0] = 437;
		bounds[1] = 445;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 442;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.parents()";
		bounds[0] = 447;
		bounds[1] = 457;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 451;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.first()";
		bounds[0] = 460;
		bounds[1] = 466;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 464;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.last()";
		bounds[0] = 468;
		bounds[1] = 474;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 472;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.traverse(NodeVisitor)";
		bounds[0] = 476;
		bounds[1] = 488;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 481;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Elements.forms()";
		bounds[0] = 490;
		bounds[1] = 501;
		bounds[2] = bounds[0] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 495;
		bounds[5] = bounds[4] - JSOUP_ELEMENTS_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
				
		//NodeTraversor
		
		methodName = "NodeTraversor.NodeTraversor(NodeVisitor)";
		bounds[0] = 14;
		bounds[1] = 20;
		bounds[2] = bounds[0] - JSOUP_NODETRAVERSOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODETRAVERSOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 18;
		bounds[5] = bounds[4] - JSOUP_NODETRAVERSOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);

		methodName = "NodeTraversor.traverse(Node)";
		bounds[0] = 22;
		bounds[1] = 47;
		bounds[2] = bounds[0] - JSOUP_NODETRAVERSOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_NODETRAVERSOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 26;
		bounds[5] = bounds[4] - JSOUP_NODETRAVERSOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);

		
		//QueryParser
		
		methodName = "QueryParser.QueryParser(String)";
		bounds[0] = 23;
		bounds[1] = 30;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 27;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.parse(String)";
		bounds[0] = 32;
		bounds[1] = 40;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 37;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.parse()";
		bounds[0] = 42;
		bounds[1] = 73;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 46;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.combinator(char)";
		bounds[0] = 75;
		bounds[1] = 125;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 75;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.consumeSubQuery()";
		bounds[0] = 127;
		bounds[1] = 140;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 127;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.findElements()";
		bounds[0] = 142;
		bounds[1] = 198;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 142;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.byId()";
		bounds[0] = 200;
		bounds[1] = 204;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 200;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.byClass()";
		bounds[0] = 206;
		bounds[1] = 210;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 206;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.byTag()";
		bounds[0] = 212;
		bounds[1] = 221;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 212;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.byAttribute()";
		bounds[0] = 223;
		bounds[1] = 255;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 223;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.allElements()";
		bounds[0] = 257;
		bounds[1] = 259;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 257;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.indexLessThan()";
		bounds[0] = 261;
		bounds[1] = 264;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 262;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.indexGreaterThan()";
		bounds[0] = 266;
		bounds[1] = 268;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 266;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.indexEquals()";
		bounds[0] = 270;
		bounds[1] = 272;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 270;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.cssNthChild(boolean,boolean)";
		bounds[0] = 278;
		bounds[1] = 309;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 278;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.consumeIndex()";
		bounds[0] = 311;
		bounds[1] = 315;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 311;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.has()";
		bounds[0] = 317;
		bounds[1] = 323;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 318;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.contains(boolean)";
		bounds[0] = 325;
		bounds[1] = 334;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 326;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.matches(boolean)";
		bounds[0] = 336;
		bounds[1] = 346;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 337;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "QueryParser.not()";
		bounds[0] = 348;
		bounds[1] = 355;
		bounds[2] = bounds[0] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 349;
		bounds[5] = bounds[4] - JSOUP_QUERYPARSER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		
		//Selector
		
		methodName = "Selector.Selector(String query, Element)";
		bounds[0] = 77;
		bounds[1] = 86;
		bounds[2] = bounds[0] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 77;
		bounds[5] = bounds[4] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Selector.Selector(Evaluator,Element)";
		bounds[0] = 88;
		bounds[1] = 94;
		bounds[2] = bounds[0] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 88;
		bounds[5] = bounds[4] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Selector.select(String,Element)";
		bounds[0] = 96;
		bounds[1] = 106;
		bounds[2] = bounds[0] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 104;
		bounds[5] = bounds[4] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Selector.select(Evaluator,Element)";
		bounds[0] = 108;
		bounds[1] = 117;
		bounds[2] = bounds[0] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 115;
		bounds[5] = bounds[4] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Selector.select(String,Iterable<Element>)";
		bounds[0] = 119;
		bounds[1] = 136;
		bounds[2] = bounds[0] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 126;
		bounds[5] = bounds[4] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Selector.select()";
		bounds[0] = 138;
		bounds[1] = 140;
		bounds[2] = bounds[0] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 138;
		bounds[5] = bounds[4] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		methodName = "Selector$1.SelectorParseException(String,Object)";
		bounds[0] = 160;
		bounds[1] = 162;
		bounds[2] = bounds[0] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 160;
		bounds[5] = bounds[4] - JSOUP_SELECTOR_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		jsoupMethodSequence.add(methodName);
		
		return methods;
	}
	
	private static Map<Integer,int[]> loadjsoupLines(){
		Map<Integer,int[]> lines = new HashMap<Integer,int[]>();
		int bounds[] = new int[LINE_BOUND_SIZE];
		int lineNumber = 0;
		
		lineNumber = 514;
		bounds[0] = 506;
		bounds[1] = 503;
		bounds[2] = 521;
		bounds[3] = 495;
		bounds[4] = 513;
		bounds[5] = 512;
		bounds[6] = 504;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 515;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 507;
		bounds[1] = 503;
		bounds[2] = 521;
		bounds[3] = 495;
		bounds[4] = 513;
		bounds[5] = 512;
		bounds[6] = 504;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 516;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 508;
		bounds[1] = 503;
		bounds[2] = 521;
		bounds[3] = 495;
		bounds[4] = 513;
		bounds[5] = 512;
		bounds[6] = 504;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 517;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 509;
		bounds[1] = 503;
		bounds[2] = 521;
		bounds[3] = 495;
		bounds[4] = 513;
		bounds[5] = 512;
		bounds[6] = 504;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 518;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 510;
		bounds[1] = 503;
		bounds[2] = 521;
		bounds[3] = 495;
		bounds[4] = 513;
		bounds[5] = 512;
		bounds[6] = 504;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 1190;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 1182;
		bounds[1] = 1185;
		bounds[2] = 1193;
		bounds[3] = 1177;
		bounds[4] = 1185;
		bounds[5] = 1185;
		bounds[6] = 1177;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 1192;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 1184;
		bounds[1] = 1185;
		bounds[2] = 1193;
		bounds[3] = 1177;
		bounds[4] = 1185;
		bounds[5] = 1185;
		bounds[6] = 1177;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 167;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 165;
		bounds[1] = 160;
		bounds[2] = 173;
		bounds[3] = 158;
		bounds[4] = 171;
		bounds[5] = 166;
		bounds[6] = 164;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 168;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 166;
		bounds[1] = 160;
		bounds[2] = 173;
		bounds[3] = 158;
		bounds[4] = 171;
		bounds[5] = 166;
		bounds[6] = 164;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 170;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 168;
		bounds[1] = 160;
		bounds[2] = 173;
		bounds[3] = 158;
		bounds[4] = 171;
		bounds[5] = 166;
		bounds[6] = 164;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 172;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 170;
		bounds[1] = 160;
		bounds[2] = 173;
		bounds[3] = 158;
		bounds[4] = 171;
		bounds[5] = 166;
		bounds[6] = 164;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 513;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 505;
		bounds[1] = 503;
		bounds[2] = 521;
		bounds[3] = 495;
		bounds[4] = 513;
		bounds[5] = 512;
		bounds[6] = 504;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 182;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 179;
		bounds[1] = 181;
		bounds[2] = 197;
		bounds[3] = 178;
		bounds[4] = 194;
		bounds[5] = 181;
		bounds[6] = 178;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 569;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 561;
		bounds[1] = 568;
		bounds[2] = 579;
		bounds[3] = 560;
		bounds[4] = 571;
		bounds[5] = 568;
		bounds[6] = 560;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 570;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 562;
		bounds[1] = 568;
		bounds[2] = 579;
		bounds[3] = 560;
		bounds[4] = 571;
		bounds[5] = 568;
		bounds[6] = 560;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 572;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 564;
		bounds[1] = 568;
		bounds[2] = 579;
		bounds[3] = 560;
		bounds[4] = 571;
		bounds[5] = 568;
		bounds[6] = 560;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 573;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 565;
		bounds[1] = 568;
		bounds[2] = 579;
		bounds[3] = 560;
		bounds[4] = 571;
		bounds[5] = 568;
		bounds[6] = 560;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 574;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 566;
		bounds[1] = 568;
		bounds[2] = 579;
		bounds[3] = 560;
		bounds[4] = 571;
		bounds[5] = 568;
		bounds[6] = 560;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 576;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 568;
		bounds[1] = 568;
		bounds[2] = 579;
		bounds[3] = 560;
		bounds[4] = 571;
		bounds[5] = 568;
		bounds[6] = 560;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 598;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 582;
		bounds[1] = 584;
		bounds[2] = 599;
		bounds[3] = 573;
		bounds[4] = 588;
		bounds[5] = 591;
		bounds[6] = 580;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 179;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 178;
		bounds[1] = 177;
		bounds[2] = 185;
		bounds[3] = 176;
		bounds[4] = 184;
		bounds[5] = 177;
		bounds[6] = 176;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 180;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 179;
		bounds[1] = 177;
		bounds[2] = 185;
		bounds[3] = 176;
		bounds[4] = 184;
		bounds[5] = 177;
		bounds[6] = 176;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 182;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 181;
		bounds[1] = 177;
		bounds[2] = 185;
		bounds[3] = 176;
		bounds[4] = 184;
		bounds[5] = 177;
		bounds[6] = 176;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 184;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 183;
		bounds[1] = 177;
		bounds[2] = 185;
		bounds[3] = 176;
		bounds[4] = 184;
		bounds[5] = 177;
		bounds[6] = 176;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 1187;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 1179;
		bounds[1] = 1185;
		bounds[2] = 1193;
		bounds[3] = 1177;
		bounds[4] = 1185;
		bounds[5] = 1185;
		bounds[6] = 1177;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 1188;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 1180;
		bounds[1] = 1185;
		bounds[2] = 1193;
		bounds[3] = 1177;
		bounds[4] = 1185;
		bounds[5] = 1185;
		bounds[6] = 1177;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 592;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 581;
		bounds[1] = 591;
		bounds[2] = 599;
		bounds[3] = 580;
		bounds[4] = 588;
		bounds[5] = 591;
		bounds[6] = 580;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 593;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 582;
		bounds[1] = 591;
		bounds[2] = 599;
		bounds[3] = 580;
		bounds[4] = 588;
		bounds[5] = 591;
		bounds[6] = 580;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 595;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 584;
		bounds[1] = 591;
		bounds[2] = 599;
		bounds[3] = 580;
		bounds[4] = 588;
		bounds[5] = 591;
		bounds[6] = 580;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 597;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 586;
		bounds[1] = 591;
		bounds[2] = 599;
		bounds[3] = 580;
		bounds[4] = 588;
		bounds[5] = 591;
		bounds[6] = 580;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 178;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 177;
		bounds[1] = 177;
		bounds[2] = 185;
		bounds[3] = 176;
		bounds[4] = 184;
		bounds[5] = 177;
		bounds[6] = 176;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 1186;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 1178;
		bounds[1] = 1185;
		bounds[2] = 1195;
		bounds[3] = 1177;
		bounds[4] = 1185;
		bounds[5] = 1185;
		bounds[6] = 1177;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 530;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 522;
		bounds[1] = 523;
		bounds[2] = 537;
		bounds[3] = 515;
		bounds[4] = 529;
		bounds[5] = 528;
		bounds[6] = 520;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 531;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 523;
		bounds[1] = 523;
		bounds[2] = 537;
		bounds[3] = 515;
		bounds[4] = 529;
		bounds[5] = 528;
		bounds[6] = 520;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 532;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 524;
		bounds[1] = 523;
		bounds[2] = 537;
		bounds[3] = 515;
		bounds[4] = 529;
		bounds[5] = 528;
		bounds[6] = 520;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 533;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 525;
		bounds[1] = 523;
		bounds[2] = 537;
		bounds[3] = 515;
		bounds[4] = 529;
		bounds[5] = 528;
		bounds[6] = 520;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
			
		lineNumber = 534;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 526;
		bounds[1] = 523;
		bounds[2] = 537;
		bounds[3] = 515;
		bounds[4] = 529;
		bounds[5] = 528;
		bounds[6] = 520;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 529;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 521;
		bounds[1] = 523;
		bounds[2] = 537;
		bounds[3] = 515;
		bounds[4] = 529;
		bounds[5] = 528;
		bounds[6] = 520;
		lines.put(lineNumber, bounds);
		jsoupLineSequence.add(String.valueOf(lineNumber));
		
		return lines;
	}
	
	
	private static Map<String,int[]> loadxstreamMethods(){
		Map<String,int[]> methods = new HashMap<String,int[]>();
		int bounds[] = new int[METHOD_BOUND_SIZE];
		String methodName = "";
		methodName = "AnnotationMapper.cacheConverter(XStreamConverter,Class)";
		bounds[0] = 449;
		bounds[1] = 518;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 450;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "SortableFieldKeySorter.sort(Class,Map)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 23;
		bounds[1] = 47;
		bounds[2] = bounds[0] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 34;
		bounds[5] = bounds[4] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.processAnnotations(Class[])";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 134;
		bounds[1] = 146;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 134;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "SortableFieldKeySorter.registerFieldOrder(Class,String[])";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 49;
		bounds[1] = 59;
		bounds[2] = bounds[0] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 57;
		bounds[5] = bounds[4] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldKey.getFieldName()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 41;
		bounds[1] = 43;
		bounds[2] = bounds[0] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 41;
		bounds[5] = bounds[4] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DependencyInjectionFactory.newInstance(Class,Object[],BitSet)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 49;
		bounds[1] = 223;
		bounds[2] = bounds[0] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 63;
		bounds[5] = bounds[4] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "NativeFieldKeySorter$1.compare(Object,Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 30;
		bounds[1] = 38;
		bounds[2] = bounds[0] - XSTREAM_NATIVEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_NATIVEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 30;
		bounds[5] = bounds[4] - XSTREAM_NATIVEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "NativeFieldKeySorter.sort(Class,Map)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 27;
		bounds[1] = 42;
		bounds[2] = bounds[0] - XSTREAM_NATIVEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_NATIVEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 27;
		bounds[5] = bounds[4] - XSTREAM_NATIVEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "OrderRetainingMap.keySet()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 69;
		bounds[1] = 71;
		bounds[2] = bounds[0] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 69;
		bounds[5] = bounds[4] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper$1.add(Type)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 210;
		bounds[1] = 215;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 210;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldKey.getDepth()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 49;
		bounds[1] = 51;
		bounds[2] = bounds[0] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 49;
		bounds[5] = bounds[4] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldKey.getOrder()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 53;
		bounds[1] = 55;
		bounds[2] = bounds[0] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 53;
		bounds[5] = bounds[4] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.toXML(Object,Writer)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 848;
		bounds[1] = 861;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 854;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "OrderRetainingMap.OrderRetainingMap()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 30;
		bounds[1] = 32;
		bounds[2] = bounds[0] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 30;
		bounds[5] = bounds[4] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//new methods beyond the best ranked ones
		
		//InitializationException
		
		methodName = "InitializationException.InitializationException(String,Throwable)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 21;
		bounds[1] = 23;
		bounds[2] = bounds[0] - XSTREAM_INITIALIZATIONEXCEPTION_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_INITIALIZATIONEXCEPTION_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 21;
		bounds[5] = bounds[4] - XSTREAM_INITIALIZATIONEXCEPTION_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "InitializationException.InitializationException(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 25;
		bounds[1] = 27;
		bounds[2] = bounds[0] - XSTREAM_INITIALIZATIONEXCEPTION_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_INITIALIZATIONEXCEPTION_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 25;
		bounds[5] = bounds[4] - XSTREAM_INITIALIZATIONEXCEPTION_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//XStream
		
		methodName = "XStream.XStream()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 329;
		bounds[1] = 337;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 335;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.XStream(ReflectionProvider)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 339;
		bounds[1] = 347;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 345;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.XStream(HierarchicalStreamDriver)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 349;
		bounds[1] = 357;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 355;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.XStream(ReflectionProvider,HierarchicalStreamDriver)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 359;
		bounds[1] = 368;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 365;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.XStream(ReflectionProvider,Mapper,HierarchicalStreamDriver)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 370;
		bounds[1] = 384;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 379;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.XStream(ReflectionProvider,HierarchicalStreamDriver,ClassLoader,Mapper)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 399;
		bounds[1] = 417;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 412;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.XStream(ReflectionProvider,HierarchicalStreamDriver,ClassLoader,Mapper,ConverterLookup,ConverterRegistry)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 419;
		bounds[1] = 459;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 432;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.buildMapper()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 461;
		bounds[1] = 494;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 461;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.buildMapperDynamically(String,Class[],Object[])";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 496;
		bounds[1] = 506;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 496;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.wrapMapper(MapperWrapper)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 508;
		bounds[1] = 510;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 508;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.useXStream11XmlFriendlyMapper()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 512;
		bounds[1] = 514;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 512;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 516;
		bounds[1] = 539;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 516;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.setupAliases()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 541;
		bounds[1] = 627;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 541;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.aliasDynamically(String,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 629;
		bounds[1] = 634;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 629;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.setupDefaultImplementations()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 636;
		bounds[1] = 645;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 636;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.setupConverters()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 647;
		bounds[1] = 759;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 647;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.registerConverterDynamically(String,int,Class[],Object[])";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 761;
		bounds[1] = 776;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 761;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.setupImmutableTypes()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 778;
		bounds[1] = 824;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 778;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.addImmutableTypeDynamically(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 826;
		bounds[1] = 835;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 826;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.setMarshallingStrategy(MarshallingStrategy)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 833;
		bounds[1] = 835;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 833;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.toXML(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 837;
		bounds[1] = 846;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 842;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.toXML(Object,OutputStream)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 863;
		bounds[1] = 876;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 869;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.marshal(Object,HierarchicalStreamWriter)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 878;
		bounds[1] = 885;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 883;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.marshal(Object,HierarchicalStreamWriter,DataHolder)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 887;
		bounds[1] = 896;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 894;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.fromXML(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 898;
		bounds[1] = 905;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 903;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.fromXML(Reader)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 907;
		bounds[1] = 914;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 912;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.fromXML(InputStream)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 916;
		bounds[1] = 923;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 921;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.fromXML(URL)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 925;
		bounds[1] = 936;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 934;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.fromXML(File)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 938;
		bounds[1] = 949;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 947;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.fromXML(String,Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 951;
		bounds[1] = 961;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 959;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.fromXML(Reader,Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 963;
		bounds[1] = 973;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 971;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.fromXML(URL,Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 975;
		bounds[1] = 989;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 987;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.fromXML(File,Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 991;
		bounds[1] = 1010;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1003;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.fromXML(InputStream,Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1012;
		bounds[1] = 1022;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1020;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.unmarshal(HierarchicalStreamReader)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1024;
		bounds[1] = 1031;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1029;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.unmarshal(HierarchicalStreamReader,Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1033;
		bounds[1] = 1043;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1041;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.unmarshal(HierarchicalStreamReader,Object,DataHolder)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1045;
		bounds[1] = 1066;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1056;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.alias(String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1068;
		bounds[1] = 1082;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1075;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.aliasType(String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1084;
		bounds[1] = 1100;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1093;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.alias(String,Class,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1102;
		bounds[1] = 1114;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1111;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.aliasPackage(String,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1116;
		bounds[1] = 1132;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1125;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.aliasField(String,Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1134;
		bounds[1] = 1149;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1142;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.aliasAttribute(String,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1151;
		bounds[1] = 1165;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1158;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.aliasSystemAttribute(String,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1167;
		bounds[1] = 1185;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1178;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.aliasAttribute(Class,String,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1187;
		bounds[1] = 1199;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1196;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.useAttributeFor(String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1201;
		bounds[1] = 1216;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1209;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.useAttributeFor(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1218;
		bounds[1] = 1233;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1226;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.useAttributeFor(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1235;
		bounds[1] = 1249;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1242;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.addDefaultImplementation(Class,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1251;
		bounds[1] = 1267;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1260;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.addImmutableType(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1269;
		bounds[1] = 1282;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1275;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.registerConverter(Converter)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1284;
		bounds[1] = 1286;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1284;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.registerConverter(Converter,int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1288;
		bounds[1] = 1292;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1288;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.registerConverter(SingleValueConverter)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1294;
		bounds[1] = 1296;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1294;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.registerConverter(SingleValueConverter,int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1298;
		bounds[1] = 1303;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1298;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.registerLocalConverter(Class,String,Converter)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1305;
		bounds[1] = 1320;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1313;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.registerLocalConverter(Class,String,SingleValueConverter)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1322;
		bounds[1] = 1334;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1330;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.getMapper()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1336;
		bounds[1] = 1345;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1343;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.getReflectionProvider()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1347;
		bounds[1] = 1355;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1353;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.getConverterLookup()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1357;
		bounds[1] = 1359;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1357;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.setMode(int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1361;
		bounds[1] = 1401;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1372;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.addImplicitCollection(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1403;
		bounds[1] = 1413;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1411;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.addImplicitCollection(Class,String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1415;
		bounds[1] = 1427;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1425;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.addImplicitCollection(Class,String,String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1429;
		bounds[1] = 1444;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1441;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.addImplicitArray(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1446;
		bounds[1] = 1455;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1453;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.addImplicitArray(Class,String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1457;
		bounds[1] = 1470;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1468;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.addImplicitArray(Class,String,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1472;
		bounds[1] = 1484;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1482;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.addImplicitMap(Class,String,Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1486;
		bounds[1] = 1499;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1497;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.addImplicitMap(Class,String,String,Class,String";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1501;
		bounds[1] = 1521;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1513;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.newDataHolder()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1523;
		bounds[1] = 1532;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1530;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.createObjectOutputStream(Writer)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1534;
		bounds[1] = 1550;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1547;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.createObjectOutputStream(HierarchicalStreamWriter)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1552;
		bounds[1] = 1568;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1565;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.createObjectOutputStream(Writer,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1570;
		bounds[1] = 1583;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1579;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.createObjectOutputStream(OutputStream)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1585;
		bounds[1] = 1601;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1598;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.createObjectOutputStream(OutputStream,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1603;
		bounds[1] = 1616;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1612;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.createObjectOutputStream(HierarchicalStreamWriter,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1618;
		bounds[1] = 1672;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1644;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.createObjectInputStream(Reader)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1674;
		bounds[1] = 1685;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1683;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.createObjectInputStream(InputStream)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1687;
		bounds[1] = 1698;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1696;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.createObjectInputStream(HierarchicalStreamReader)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1700;
		bounds[1] = 1745;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1715;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.setClassLoader(ClassLoader)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1747;
		bounds[1] = 1758;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1756;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.getClassLoader()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1760;
		bounds[1] = 1767;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1765;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.omitField(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1769;
		bounds[1] = 1783;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1776;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.processAnnotations(Class[])";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1785;
		bounds[1] = 1798;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1791;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.processAnnotations(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1800;
		bounds[1] = 1809;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1807;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.autodetectAnnotations(boolean)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1811;
		bounds[1] = 1824;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1820;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream$1.InitializationException(String,Throwable)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1830;
		bounds[1] = 1835;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1833;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.InitializationException(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1837;
		bounds[1] = 1842;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1840;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStream.readResolve()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 1845;
		bounds[1] = 1848;
		bounds[2] = bounds[0] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 1845;
		bounds[5] = bounds[4] - XSTREAM_XSTREAM_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//XStreamConverter
		
		methodName = "XStreamConverter.value()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 58;
		bounds[1] = 58;
		bounds[2] = bounds[0] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 58;
		bounds[5] = bounds[4] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStreamConverter.priority()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 59;
		bounds[1] = 59;
		bounds[2] = bounds[0] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 59;
		bounds[5] = bounds[4] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStreamConverter.types()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 60;
		bounds[1] = 71;
		bounds[2] = bounds[0] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 71;
		bounds[5] = bounds[4] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStreamConverter.strings()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 72;
		bounds[1] = 72;
		bounds[2] = bounds[0] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 72;
		bounds[5] = bounds[4] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStreamConverter.bytes()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 73;
		bounds[1] = 73;
		bounds[2] = bounds[0] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 73;
		bounds[5] = bounds[4] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStreamConverter.chars()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 74;
		bounds[1] = 74;
		bounds[2] = bounds[0] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 74;
		bounds[5] = bounds[4] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStreamConverter.shorts()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 75;
		bounds[1] = 75;
		bounds[2] = bounds[0] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 75;
		bounds[5] = bounds[4] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStreamConverter.ints()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 76;
		bounds[1] = 76;
		bounds[2] = bounds[0] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 76;
		bounds[5] = bounds[4] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStreamConverter.longs()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 77;
		bounds[1] = 77;
		bounds[2] = bounds[0] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 77;
		bounds[5] = bounds[4] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStreamConverter.floats()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 78;
		bounds[1] = 78;
		bounds[2] = bounds[0] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 78;
		bounds[5] = bounds[4] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStreamConverter.doubles()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 79;
		bounds[1] = 79;
		bounds[2] = bounds[0] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 79;
		bounds[5] = bounds[4] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "XStreamConverter.booleans()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 80;
		bounds[1] = 80;
		bounds[2] = bounds[0] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 80;
		bounds[5] = bounds[4] - XSTREAM_XSTREAMCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
				
		//BigDecimalConverter
		
		methodName = "BigDecimalConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 24;
		bounds[1] = 26;
		bounds[2] = bounds[0] - XSTREAM_BIGDECIMALCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BIGDECIMALCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 24;
		bounds[5] = bounds[4] - XSTREAM_BIGDECIMALCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "BigDecimalConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 28;
		bounds[1] = 30;
		bounds[2] = bounds[0] - XSTREAM_BIGDECIMALCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BIGDECIMALCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 28;
		bounds[5] = bounds[4] - XSTREAM_BIGDECIMALCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
				
		
		//BigIntegerConverter
		
		methodName = "BigIntegerConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 23;
		bounds[1] = 25;
		bounds[2] = bounds[0] - XSTREAM_BIGINTEGERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BIGINTEGERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 23;
		bounds[5] = bounds[4] - XSTREAM_BIGINTEGERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "BigIntegerConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 27;
		bounds[1] = 29;
		bounds[2] = bounds[0] - XSTREAM_BIGINTEGERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BIGINTEGERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 27;
		bounds[5] = bounds[4] - XSTREAM_BIGINTEGERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//BooleanConverter
		
		methodName = "BooleanConverter.BooleanConverter(String,String,boolean)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 34;
		bounds[1] = 38;
		bounds[2] = bounds[0] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 34;
		bounds[5] = bounds[4] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "BooleanConverter.BooleanConverter()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 40;
		bounds[1] = 42;
		bounds[2] = bounds[0] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 40;
		bounds[5] = bounds[4] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "BooleanConverter.shouldConvert(Class,Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 44;
		bounds[1] = 46;
		bounds[2] = bounds[0] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 44;
		bounds[5] = bounds[4] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "BooleanConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 48;
		bounds[1] = 50;
		bounds[2] = bounds[0] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 48;
		bounds[5] = bounds[4] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "BooleanConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 52;
		bounds[1] = 58;
		bounds[2] = bounds[0] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 52;
		bounds[5] = bounds[4] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "BooleanConverter.toString(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 60;
		bounds[1] = 63;
		bounds[2] = bounds[0] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 60;
		bounds[5] = bounds[4] - XSTREAM_BOOLEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//ByteConverter
		
		methodName = "ByteConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 22;
		bounds[1] = 24;
		bounds[2] = bounds[0] - XSTREAM_BYTECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BYTECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 22;
		bounds[5] = bounds[4] - XSTREAM_BYTECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ByteConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 26;
		bounds[1] = 32;
		bounds[2] = bounds[0] - XSTREAM_BYTECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BYTECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 32;
		bounds[5] = bounds[4] - XSTREAM_BYTECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//CharConverter
		
		methodName = "CharConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 30;
		bounds[1] = 32;
		bounds[2] = bounds[0] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 30;
		bounds[5] = bounds[4] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CharConverter.marshal(Object,HierarchicalStreamWriter,MarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 34;
		bounds[1] = 36;
		bounds[2] = bounds[0] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 34;
		bounds[5] = bounds[4] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CharConverter.unmarshal(HierarchicalStreamReader,UnmarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 38;
		bounds[1] = 45;
		bounds[2] = bounds[0] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 38;
		bounds[5] = bounds[4] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CharConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 47;
		bounds[1] = 53;
		bounds[2] = bounds[0] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 47;
		bounds[5] = bounds[4] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CharConverter.toString(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 55;
		bounds[1] = 58;
		bounds[2] = bounds[0] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 55;
		bounds[5] = bounds[4] - XSTREAM_CHARCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
				
		//DateConverter
		
		methodName = "DateConverter.DateConverter()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 88;
		bounds[1] = 93;
		bounds[2] = bounds[0] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 91;
		bounds[5] = bounds[4] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DateConverter.DateConverter(TimeZone)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 95;
		bounds[1] = 104;
		bounds[2] = bounds[0] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 102;
		bounds[5] = bounds[4] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DateConverter.DateConverter(boolean)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 106;
		bounds[1] = 114;
		bounds[2] = bounds[0] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 112;
		bounds[5] = bounds[4] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DateConverter.DateConverter(String,String[])";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 116;
		bounds[1] = 124;
		bounds[2] = bounds[0] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 122;
		bounds[5] = bounds[4] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DateConverter.DateConverter(String,String[],TimeZone)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 126;
		bounds[1] = 135;
		bounds[2] = bounds[0] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 133;
		bounds[5] = bounds[4] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DateConverter.DateConverter(String,String[],boolean)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 137;
		bounds[1] = 147;
		bounds[2] = bounds[0] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 145;
		bounds[5] = bounds[4] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DateConverter.DateConverter(String,String[],TimeZone,boolean)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 149;
		bounds[1] = 161;
		bounds[2] = bounds[0] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 158;
		bounds[5] = bounds[4] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DateConverter.DateConverter(String,String,String[],Locale,TimeZone,boolean)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 163;
		bounds[1] = 194;
		bounds[2] = bounds[0] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 175;
		bounds[5] = bounds[4] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DateConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 196;
		bounds[1] = 198;
		bounds[2] = bounds[0] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 196;
		bounds[5] = bounds[4] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DateConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 200;
		bounds[1] = 224;
		bounds[2] = bounds[0] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 200;
		bounds[5] = bounds[4] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DateConverter.toString(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 226;
		bounds[1] = 233;
		bounds[2] = bounds[0] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 226;
		bounds[5] = bounds[4] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DateConverter.appendErrors(ErrorWriter)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 235;
		bounds[1] = 243;
		bounds[2] = bounds[0] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 235;
		bounds[5] = bounds[4] - XSTREAM_DATECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//DoubleConverter
		
		methodName = "DoubleConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 22;
		bounds[1] = 24;
		bounds[2] = bounds[0] - XSTREAM_DOUBLECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DOUBLECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 22;
		bounds[5] = bounds[4] - XSTREAM_DOUBLECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DoubleConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 26;
		bounds[1] = 28;
		bounds[2] = bounds[0] - XSTREAM_DOUBLECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DOUBLECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 26;
		bounds[5] = bounds[4] - XSTREAM_DOUBLECONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//FloatConverter
		
		methodName = "FloatConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 22;
		bounds[1] = 24;
		bounds[2] = bounds[0] - XSTREAM_FLOATCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FLOATCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 22;
		bounds[5] = bounds[4] - XSTREAM_FLOATCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FloatConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 26;
		bounds[1] = 28;
		bounds[2] = bounds[0] - XSTREAM_FLOATCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FLOATCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 26;
		bounds[5] = bounds[4] - XSTREAM_FLOATCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//IntConverter
		
		methodName = "IntConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 22;
		bounds[1] = 24;
		bounds[2] = bounds[0] - XSTREAM_INTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_INTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 22;
		bounds[5] = bounds[4] - XSTREAM_INTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "IntConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 26;
		bounds[1] = 32;
		bounds[2] = bounds[0] - XSTREAM_INTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_INTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 26;
		bounds[5] = bounds[4] - XSTREAM_INTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//LongConverter
		
		methodName = "LongConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 22;
		bounds[1] = 24;
		bounds[2] = bounds[0] - XSTREAM_LONGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_LONGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 22;
		bounds[5] = bounds[4] - XSTREAM_LONGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "LongConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 26;
		bounds[1] = 28;
		bounds[2] = bounds[0] - XSTREAM_LONGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_LONGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 26;
		bounds[5] = bounds[4] - XSTREAM_LONGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//ShortConverter
		
		methodName = "ShortConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 22;
		bounds[1] = 24;
		bounds[2] = bounds[0] - XSTREAM_SHORTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_SHORTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 22;
		bounds[5] = bounds[4] - XSTREAM_SHORTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ShortConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 26;
		bounds[1] = 32;
		bounds[2] = bounds[0] - XSTREAM_SHORTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_SHORTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 26;
		bounds[5] = bounds[4] - XSTREAM_SHORTCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//StringBufferConverter
		
		methodName = "StringBufferConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 21;
		bounds[1] = 23;
		bounds[2] = bounds[0] - XSTREAM_STRINGBUFFERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_STRINGBUFFERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 21;
		bounds[5] = bounds[4] - XSTREAM_STRINGBUFFERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "StringBufferConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 25;
		bounds[1] = 27;
		bounds[2] = bounds[0] - XSTREAM_STRINGBUFFERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_STRINGBUFFERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 25;
		bounds[5] = bounds[4] - XSTREAM_STRINGBUFFERCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//StringConverter
		
		methodName = "StringConverter.StringConverter(Map,int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 45;
		bounds[1] = 55;
		bounds[2] = bounds[0] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 52;
		bounds[5] = bounds[4] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "StringConverter.StringConverter(Map)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 57;
		bounds[1] = 64;
		bounds[2] = bounds[0] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 62;
		bounds[5] = bounds[4] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "StringConverter.StringConverter(int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 66;
		bounds[1] = 74;
		bounds[2] = bounds[0] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 72;
		bounds[5] = bounds[4] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "StringConverter.StringConverter()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 76;
		bounds[1] = 81;
		bounds[2] = bounds[0] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 79;
		bounds[5] = bounds[4] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "StringConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 83;
		bounds[1] = 85;
		bounds[2] = bounds[0] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 83;
		bounds[5] = bounds[4] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "StringConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 87;
		bounds[1] = 102;
		bounds[2] = bounds[0] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 87;
		bounds[5] = bounds[4] - XSTREAM_STRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//URIConverter
		
		methodName = "URIConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 26;
		bounds[1] = 28;
		bounds[2] = bounds[0] - XSTREAM_URICONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_URICONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 26;
		bounds[5] = bounds[4] - XSTREAM_URICONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "URIConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 30;
		bounds[1] = 36;
		bounds[2] = bounds[0] - XSTREAM_URICONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_URICONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 30;
		bounds[5] = bounds[4] - XSTREAM_URICONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//URLConverter
		
		methodName = "URLConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 26;
		bounds[1] = 28;
		bounds[2] = bounds[0] - XSTREAM_URLCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_URLCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 26;
		bounds[5] = bounds[4] - XSTREAM_URLCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "URLConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 30;
		bounds[1] = 36;
		bounds[2] = bounds[0] - XSTREAM_URLCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_URLCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 30;
		bounds[5] = bounds[4] - XSTREAM_URLCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//AbstractCollectionConverter
		
		methodName = "AbstractCollectionConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 38;
		bounds[1] = 38;
		bounds[2] = bounds[0] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 38;
		bounds[5] = bounds[4] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AbstractCollectionConverter.AbstractCollectionConverter(Mapper)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 40;
		bounds[1] = 42;
		bounds[2] = bounds[0] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 40;
		bounds[5] = bounds[4] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AbstractCollectionConverter.mapper()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 44;
		bounds[1] = 46;
		bounds[2] = bounds[0] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 44;
		bounds[5] = bounds[4] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AbstractCollectionConverter.marshal(Object,HierarchicalStreamWriter,MarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 48;
		bounds[1] = 48;
		bounds[2] = bounds[0] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 48;
		bounds[5] = bounds[4] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AbstractCollectionConverter.unmarshal(HierarchicalStreamReader,UnmarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 50;
		bounds[1] = 50;
		bounds[2] = bounds[0] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 50;
		bounds[5] = bounds[4] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AbstractCollectionConverter.writeItem(Object,MarshallingContext,HierarchicalStreamWriter)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 54;
		bounds[1] = 67;
		bounds[2] = bounds[0] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 54;
		bounds[5] = bounds[4] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AbstractCollectionConverter.readItem(HierarchicalStreamReader,UnmarshallingContext,Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 69;
		bounds[1] = 72;
		bounds[2] = bounds[0] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 69;
		bounds[5] = bounds[4] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AbstractCollectionConverter.createCollection(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 74;
		bounds[1] = 83;
		bounds[2] = bounds[0] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 74;
		bounds[5] = bounds[4] - XSTREAM_ABSTRACTCOLLECTIONCONVETER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//BitSetConverter
		
		methodName = "BitSetConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 31;
		bounds[1] = 33;
		bounds[2] = bounds[0] - XSTREAM_BITSETCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BITSETCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 31;
		bounds[5] = bounds[4] - XSTREAM_BITSETCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "BitSetConverter.marshal(Object,HierarchicalStreamWriter,MarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 35;
		bounds[1] = 50;
		bounds[2] = bounds[0] - XSTREAM_BITSETCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BITSETCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 35;
		bounds[5] = bounds[4] - XSTREAM_BITSETCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "BitSetConverter.unmarshal(HierarchicalStreamReader,UnmarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 52;
		bounds[1] = 60;
		bounds[2] = bounds[0] - XSTREAM_BITSETCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_BITSETCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 52;
		bounds[5] = bounds[4] - XSTREAM_BITSETCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//CollectionConverter
		
		methodName = "CollectionConverter.CollectionConverter(Mapper)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 39;
		bounds[1] = 41;
		bounds[2] = bounds[0] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 39;
		bounds[5] = bounds[4] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CollectionConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 43;
		bounds[1] = 49;
		bounds[2] = bounds[0] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 43;
		bounds[5] = bounds[4] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CollectionConverter.marshal(Object,HierarchicalStreamWriter,MarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 51;
		bounds[1] = 57;
		bounds[2] = bounds[0] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 51;
		bounds[5] = bounds[4] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CollectionConverter.unmarshal(HierarchicalStreamReader,UnmarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 59;
		bounds[1] = 63;
		bounds[2] = bounds[0] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 59;
		bounds[5] = bounds[4] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CollectionConverter.populateCollection(HierarchicalStreamReader,UnmarshallingContext,Collection)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 65;
		bounds[1] = 67;
		bounds[2] = bounds[0] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 65;
		bounds[5] = bounds[4] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CollectionConverter.populateCollection(HierarchicalStreamReader,UnmarshallingContext,Collection,Collection)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 69;
		bounds[1] = 75;
		bounds[2] = bounds[0] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 69;
		bounds[5] = bounds[4] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CollectionConverter.addCurrentElementToCollection(HierarchicalStreamReader,UnmarshallingContext,Collection,Collection)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 77;
		bounds[1] = 81;
		bounds[2] = bounds[0] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 77;
		bounds[5] = bounds[4] - XSTREAM_COLLECTIONCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//MapConverter
		
		methodName = "MapConverter.MapConverter(Mapper)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 39;
		bounds[1] = 41;
		bounds[2] = bounds[0] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 39;
		bounds[5] = bounds[4] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 43;
		bounds[1] = 50;
		bounds[2] = bounds[0] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 43;
		bounds[5] = bounds[4] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapConverter.marshal(Object,HierarchicalStreamWriter,MarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 52;
		bounds[1] = 63;
		bounds[2] = bounds[0] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 52;
		bounds[5] = bounds[4] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapConverter.unmarshal(HierarchicalStreamReader,UnmarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 65;
		bounds[1] = 69;
		bounds[2] = bounds[0] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 65;
		bounds[5] = bounds[4] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapConverter.populateMap(HierarchicalStreamReader,UnmarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 71;
		bounds[1] = 73;
		bounds[2] = bounds[0] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 71;
		bounds[5] = bounds[4] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapConverter.populateMap(HierarchicalStreamReader,UnmarshallingContext,Map,Map)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 75;
		bounds[1] = 81;
		bounds[2] = bounds[0] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 75;
		bounds[5] = bounds[4] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapConverter.putCurrentEntryIntoMap(HierarchicalStreamReader,UnmarshallingContext,Map,Map)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 83;
		bounds[1] = 94;
		bounds[2] = bounds[0] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 83;
		bounds[5] = bounds[4] - XSTREAM_MAPCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//ToStringConverter
		
		methodName = "ToStringConverter.ToStringConverter(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 32;
		bounds[1] = 35;
		bounds[2] = bounds[0] - XSTREAM_TOSTRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_TOSTRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 32;
		bounds[5] = bounds[4] - XSTREAM_TOSTRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ToStringConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 36;
		bounds[1] = 38;
		bounds[2] = bounds[0] - XSTREAM_TOSTRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_TOSTRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 36;
		bounds[5] = bounds[4] - XSTREAM_TOSTRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ToStringConverter.toString(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 39;
		bounds[1] = 41;
		bounds[2] = bounds[0] - XSTREAM_TOSTRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_TOSTRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 39;
		bounds[5] = bounds[4] - XSTREAM_TOSTRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ToStringConverter.fromString(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 43;
		bounds[1] = 53;
		bounds[2] = bounds[0] - XSTREAM_TOSTRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_TOSTRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 43;
		bounds[5] = bounds[4] - XSTREAM_TOSTRINGCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//JavaBeanConverter
		
		methodName = "JavaBeanConverter.JavaBeanConverter(Mapper)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 50;
		bounds[1] = 52;
		bounds[2] = bounds[0] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 50;
		bounds[5] = bounds[4] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "JavaBeanConverter.JavaBeanConverter(Mapper,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 54;
		bounds[1] = 56;
		bounds[2] = bounds[0] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 54;
		bounds[5] = bounds[4] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "JavaBeanConverter.JavaBeanConverter(Mapper,JavaBeanProvider)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 58;
		bounds[1] = 60;
		bounds[2] = bounds[0] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 58;
		bounds[5] = bounds[4] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "JavaBeanConverter.JavaBeanConverter(Mapper,JavaBeanProvider,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 62;
		bounds[1] = 66;
		bounds[2] = bounds[0] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 62;
		bounds[5] = bounds[4] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "JavaBeanConverter.JavaBeanConverter(Mapper,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 68;
		bounds[1] = 74;
		bounds[2] = bounds[0] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 71;
		bounds[5] = bounds[4] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "JavaBeanConverter.canConvert(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 76;
		bounds[1] = 82;
		bounds[2] = bounds[0] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 80;
		bounds[5] = bounds[4] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "JavaBeanConverter.marshal(Object,HierarchicalStreamWriter,MarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 84;
		bounds[1] = 110;
		bounds[2] = bounds[0] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 84;
		bounds[5] = bounds[4] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "JavaBeanConverter.unmarshal(HierarchicalStreamReader,UnmarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 112;
		bounds[1] = 145;
		bounds[2] = bounds[0] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 112;
		bounds[5] = bounds[4] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "JavaBeanConverter.instantiateNewInstance(UnmarshallingContext)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 147;
		bounds[1] = 153;
		bounds[2] = bounds[0] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 147;
		bounds[5] = bounds[4] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "JavaBeanConverter.determineType(HierarchicalStreamReader,Object,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 155;
		bounds[1] = 163;
		bounds[2] = bounds[0] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 155;
		bounds[5] = bounds[4] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "JavaBeanConverter$1.DuplicateFieldException(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 169;
		bounds[1] = 171;
		bounds[2] = bounds[0] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 169;
		bounds[5] = bounds[4] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "JavaBeanConverter$2.DuplicatePropertyException(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 181;
		bounds[1] = 184;
		bounds[2] = bounds[0] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 181;
		bounds[5] = bounds[4] - XSTREAM_JAVABEANCONVERTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//FieldDictionary
		
		methodName = "FieldDictionary.FieldDictionary()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 42;
		bounds[1] = 44;
		bounds[2] = bounds[0] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 42;
		bounds[5] = bounds[4] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldDictionary.FieldDictionary(FieldKeySorter)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 46;
		bounds[1] = 49;
		bounds[2] = bounds[0] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 46;
		bounds[5] = bounds[4] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldDictionary.init()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 51;
		bounds[1] = 56;
		bounds[2] = bounds[0] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 51;
		bounds[5] = bounds[4] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldDictionary.serializableFieldsFor(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 58;
		bounds[1] = 67;
		bounds[2] = bounds[0] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 65;
		bounds[5] = bounds[4] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldDictionary.fieldsFor(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 69;
		bounds[1] = 77;
		bounds[2] = bounds[0] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 75;
		bounds[5] = bounds[4] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldDictionary.field(Class,String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 79;
		bounds[1] = 98;
		bounds[2] = bounds[0] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 91;
		bounds[5] = bounds[4] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldDictionary.fieldOrNull(Class,String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 100;
		bounds[1] = 118;
		bounds[2] = bounds[0] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 112;
		bounds[5] = bounds[4] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldDictionary.buildMap(Class,boolean)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 120;
		bounds[1] = 178;
		bounds[2] = bounds[0] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 120;
		bounds[5] = bounds[4] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldDictionary.flushCache()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 180;
		bounds[1] = 187;
		bounds[2] = bounds[0] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 180;
		bounds[5] = bounds[4] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldDictionary.readResolve()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 189;
		bounds[1] = 192;
		bounds[2] = bounds[0] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 189;
		bounds[5] = bounds[4] - XSTREAM_FIELDDICTIONARY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//FieldKey
		
		methodName = "FieldKey.FieldKey(String,Class,int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 25;
		bounds[1] = 39;
		bounds[2] = bounds[0] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 25;
		bounds[5] = bounds[4] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldKey.getDeclaringClass()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 45;
		bounds[1] = 47;
		bounds[2] = bounds[0] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 45;
		bounds[5] = bounds[4] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldKey.equals(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 57;
		bounds[1] = 69;
		bounds[2] = bounds[0] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 57;
		bounds[5] = bounds[4] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldKey.hashCode()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 71;
		bounds[1] = 76;
		bounds[2] = bounds[0] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 71;
		bounds[5] = bounds[4] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FieldKey.toString()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 78;
		bounds[1] = 90;
		bounds[2] = bounds[0] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 78;
		bounds[5] = bounds[4] - XSTREAM_FIELDKEY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//ImmutableFieldKeySorter
		
		methodName = "ImmutableFieldKeySorter.sort(Class,Map)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 23;
		bounds[1] = 25;
		bounds[2] = bounds[0] - XSTREAM_IMMUTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_IMMUTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 23;
		bounds[5] = bounds[4] - XSTREAM_IMMUTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		

		//SortableFieldKeySorter
		
		methodName = "SortableFieldKeySorter$1.FieldComparator(String[]).";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 65;
		bounds[1] = 67;
		bounds[2] = bounds[0] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 65;
		bounds[5] = bounds[4] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "SortableFieldKeySorter$1.compare(String,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 69;
		bounds[1] = 85;
		bounds[2] = bounds[0] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 69;
		bounds[5] = bounds[4] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "SortableFieldKeySorter$1.compare(Object,Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 87;
		bounds[1] = 90;
		bounds[2] = bounds[0] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 87;
		bounds[5] = bounds[4] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "SortableFieldKeySorter.flushCache()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 94;
		bounds[1] = 96;
		bounds[2] = bounds[0] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 94;
		bounds[5] = bounds[4] - XSTREAM_SORTABLEFIELDKEYSORTER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
				
		
		//Cloneables
		
		methodName = "Cloneables.clone(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 27;
		bounds[1] = 56;
		bounds[2] = bounds[0] - XSTREAM_CLONEABLES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CLONEABLES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 27;
		bounds[5] = bounds[4] - XSTREAM_CLONEABLES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "Cloneables.cloneIfPossible(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 58;
		bounds[1] = 61;
		bounds[2] = bounds[0] - XSTREAM_CLONEABLES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CLONEABLES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 58;
		bounds[5] = bounds[4] - XSTREAM_CLONEABLES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//CompositeClassLoader
		
		methodName = "CompositeClassLoader.CompositeClassLoader()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 56;
		bounds[1] = 59;
		bounds[2] = bounds[0] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 56;
		bounds[5] = bounds[4] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CompositeClassLoader.add(ClassLoader)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 61;
		bounds[1] = 70;
		bounds[2] = bounds[0] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 65;
		bounds[5] = bounds[4] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CompositeClassLoader.addInternal(ClassLoader)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 72;
		bounds[1] = 85;
		bounds[2] = bounds[0] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 72;
		bounds[5] = bounds[4] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CompositeClassLoader.loadClass(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 87;
		bounds[1] = 133;
		bounds[2] = bounds[0] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 87;
		bounds[5] = bounds[4] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "CompositeClassLoader.cleanup()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 135;
		bounds[1] = 141;
		bounds[2] = bounds[0] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 135;
		bounds[5] = bounds[4] - XSTREAM_COMPOSITECLASSLOADER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//DependencyInjectionFactory
		
		methodName = "DependencyInjectionFactory.newInstance(Class,Object[])";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 32;
		bounds[1] = 47;
		bounds[2] = bounds[0] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 45;
		bounds[5] = bounds[4] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DependencyInjectionFactory.clear(BitSet)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 225;
		bounds[1] = 231;
		bounds[2] = bounds[0] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 225;
		bounds[5] = bounds[4] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DependencyInjectionFactory.TypedValue(Class,Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 237;
		bounds[1] = 241;
		bounds[2] = bounds[0] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 237;
		bounds[5] = bounds[4] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "DependencyInjectionFactory.toString()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 243;
		bounds[1] = 246;
		bounds[2] = bounds[0] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 243;
		bounds[5] = bounds[4] - XSTREAM_DEPENDENCYINJECTIONFACTORY_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//FastField
		
		methodName = "FastField.FastField(String,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 17;
		bounds[1] = 20;
		bounds[2] = bounds[0] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 17;
		bounds[5] = bounds[4] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastField.FastField(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 22;
		bounds[1] = 24;
		bounds[2] = bounds[0] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 22;
		bounds[5] = bounds[4] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastField.getName()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 26;
		bounds[1] = 51;
		bounds[2] = bounds[0] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 26;
		bounds[5] = bounds[4] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastField.hashCode()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 53;
		bounds[1] = 55;
		bounds[2] = bounds[0] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 53;
		bounds[5] = bounds[4] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastField.toString()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 57;
		bounds[1] = 59;
		bounds[2] = bounds[0] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 57;
		bounds[5] = bounds[4] - XSTREAM_FASTFIELD_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//FastStack
		
		methodName = "FastStack.FastStack(int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 25;
		bounds[1] = 27;
		bounds[2] = bounds[0] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 25;
		bounds[5] = bounds[4] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastStack.push(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 29;
		bounds[1] = 35;
		bounds[2] = bounds[0] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 29;
		bounds[5] = bounds[4] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastStack.popSilently()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 37;
		bounds[1] = 39;
		bounds[2] = bounds[0] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 37;
		bounds[5] = bounds[4] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastStack.pop()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 41;
		bounds[1] = 45;
		bounds[2] = bounds[0] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 41;
		bounds[5] = bounds[4] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastStack.peek()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 47;
		bounds[1] = 49;
		bounds[2] = bounds[0] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 47;
		bounds[5] = bounds[4] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastStack.replace(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 51;
		bounds[1] = 55;
		bounds[2] = bounds[0] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 51;
		bounds[5] = bounds[4] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastStack.replaceSilently(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 57;
		bounds[1] = 59;
		bounds[2] = bounds[0] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 57;
		bounds[5] = bounds[4] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastStack.size()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 61;
		bounds[1] = 63;
		bounds[2] = bounds[0] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 61;
		bounds[5] = bounds[4] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastStack.hasStuff()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 65;
		bounds[1] = 67;
		bounds[2] = bounds[0] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 65;
		bounds[5] = bounds[4] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastStack.get(int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 69;
		bounds[1] = 71;
		bounds[2] = bounds[0] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 69;
		bounds[5] = bounds[4] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastStack.resizeStack(int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 73;
		bounds[1] = 77;
		bounds[2] = bounds[0] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 73;
		bounds[5] = bounds[4] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "FastStack.toString()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 79;
		bounds[1] = 89;
		bounds[2] = bounds[0] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 79;
		bounds[5] = bounds[4] - XSTREAM_FASTSTACK_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//OrderRetainingMap
		
		methodName = "OrderRetainingMap.OrderRetainingMap(Map)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 34;
		bounds[1] = 37;
		bounds[2] = bounds[0] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 34;
		bounds[5] = bounds[4] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "OrderRetainingMap.put(Object,Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 39;
		bounds[1] = 48;
		bounds[2] = bounds[0] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 39;
		bounds[5] = bounds[4] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "OrderRetainingMap.remove(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 50;
		bounds[1] = 57;
		bounds[2] = bounds[0] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 50;
		bounds[5] = bounds[4] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "OrderRetainingMap.clear()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 59;
		bounds[1] = 63;
		bounds[2] = bounds[0] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 59;
		bounds[5] = bounds[4] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "OrderRetainingMap.values()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 65;
		bounds[1] = 67;
		bounds[2] = bounds[0] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 65;
		bounds[5] = bounds[4] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "OrderRetainingMap.entrySet()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 73;
		bounds[1] = 82;
		bounds[2] = bounds[0] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 73;
		bounds[5] = bounds[4] - XSTREAM_ORDERRETAININGMAP_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//Primitives
		
		methodName = "Primitives.box(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 61;
		bounds[1] = 69;
		bounds[2] = bounds[0] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 67;
		bounds[5] = bounds[4] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "Primitives.unbox(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 71;
		bounds[1] = 79;
		bounds[2] = bounds[0] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 77;
		bounds[5] = bounds[4] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "Primitives.isBoxed(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 81;
		bounds[1] = 90;
		bounds[2] = bounds[0] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 88;
		bounds[5] = bounds[4] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "Primitives.primitiveType(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 92;
		bounds[1] = 101;
		bounds[2] = bounds[0] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 99;
		bounds[5] = bounds[4] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "Primitives.representingChar(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 103;
		bounds[1] = 113;
		bounds[2] = bounds[0] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 110;
		bounds[5] = bounds[4] - XSTREAM_PRIMITIVES_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//QuickWriter
		
		methodName = "QuickWriter.QuickWriter(Writer)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 25;
		bounds[1] = 27;
		bounds[2] = bounds[0] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 25;
		bounds[5] = bounds[4] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "QuickWriter.QuickWriter(Writer,int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 29;
		bounds[1] = 32;
		bounds[2] = bounds[0] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 29;
		bounds[5] = bounds[4] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "QuickWriter.write(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 34;
		bounds[1] = 45;
		bounds[2] = bounds[0] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 34;
		bounds[5] = bounds[4] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "QuickWriter.write(char)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 47;
		bounds[1] = 56;
		bounds[2] = bounds[0] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 47;
		bounds[5] = bounds[4] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "QuickWriter.write(char[])";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 58;
		bounds[1] = 69;
		bounds[2] = bounds[0] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 58;
		bounds[5] = bounds[4] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "QuickWriter.flush()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 71;
		bounds[1] = 79;
		bounds[2] = bounds[0] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 71;
		bounds[5] = bounds[4] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "QuickWriter.close()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 81;
		bounds[1] = 89;
		bounds[2] = bounds[0] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 81;
		bounds[5] = bounds[4] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "QuickWriter.raw(char[])";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 91;
		bounds[1] = 98;
		bounds[2] = bounds[0] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 91;
		bounds[5] = bounds[4] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "QuickWriter.raw(char)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 100;
		bounds[1] = 107;
		bounds[2] = bounds[0] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 100;
		bounds[5] = bounds[4] - XSTREAM_QUICKWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//WeakCache
		
		methodName = "WeakCache.WeakCache()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 36;
		bounds[1] = 44;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 42;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.WeakCache(Map)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 46;
		bounds[1] = 54;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 52;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.get(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 56;
		bounds[1] = 59;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 56;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.put(Object,Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 61;
		bounds[1] = 64;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 61;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.remove(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 66;
		bounds[1] = 69;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 66;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.createReference(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 71;
		bounds[1] = 73;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 71;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.containsValue(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 75;
		bounds[1] = 84;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 75;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.size()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 86;
		bounds[1] = 101;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 86;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.values()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 103;
		bounds[1] = 116;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 103;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.entrySet()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 118;
		bounds[1] = 146;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 118;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.iterate(Visitor,int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 148;
		bounds[1] = 172;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 148;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.containsKey(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 178;
		bounds[1] = 180;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 178;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.clear()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 182;
		bounds[1] = 184;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 182;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.keySet()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 186;
		bounds[1] = 188;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 186;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.equals(Object)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 190;
		bounds[1] = 192;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 190;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.hashCode()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 194;
		bounds[1] = 196;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 194;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "WeakCache.toString()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 198;
		bounds[1] = 200;
		bounds[2] = bounds[0] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 198;
		bounds[5] = bounds[4] - XSTREAM_WEAKCACHE_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//PathTracker
		
		methodName = "PathTracker.PathTracker()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 55;
		bounds[1] = 57;
		bounds[2] = bounds[0] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 55;
		bounds[5] = bounds[4] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PathTracker.PathTracker(int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 59;
		bounds[1] = 68;
		bounds[2] = bounds[0] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 64;
		bounds[5] = bounds[4] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PathTracker.pushElement(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 70;
		bounds[1] = 92;
		bounds[2] = bounds[0] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 75;
		bounds[5] = bounds[4] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PathTracker.popElement()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 94;
		bounds[1] = 102;
		bounds[2] = bounds[0] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 97;
		bounds[5] = bounds[4] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PathTracker.peekElement()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 104;
		bounds[1] = 112;
		bounds[2] = bounds[0] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 110;
		bounds[5] = bounds[4] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PathTracker.peekElement(int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 114;
		bounds[1] = 138;
		bounds[2] = bounds[0] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 122;
		bounds[5] = bounds[4] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PathTracker.depth()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 140;
		bounds[1] = 148;
		bounds[2] = bounds[0] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 146;
		bounds[5] = bounds[4] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PathTracker.resizeStacks(int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 150;
		bounds[1] = 159;
		bounds[2] = bounds[0] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 150;
		bounds[5] = bounds[4] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PathTracker.getPath()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 161;
		bounds[1] = 175;
		bounds[2] = bounds[0] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 164;
		bounds[5] = bounds[4] - XSTREAM_PATHTRACKER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//PrettyPrintWriter
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,int,char[],NameCoder,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 73;
		bounds[1] = 84;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 73;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,char[],String,XmlFriendlyReplacer)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 86;
		bounds[1] = 93;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 90;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,int,char[],NameCoder)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 95;
		bounds[1] = 101;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 98;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,int,char[],XmlFriendlyReplacer)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 103;
		bounds[1] = 110;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 107;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,char[],String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 112;
		bounds[1] = 117;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 115;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,int,char[])";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 119;
		bounds[1] = 124;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 122;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,char[])";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 126;
		bounds[1] = 128;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 126;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,String,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 130;
		bounds[1] = 135;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 133;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,int,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 137;
		bounds[1] = 142;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 140;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 144;
		bounds[1] = 146;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 144;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,int,NameCoder)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 148;
		bounds[1] = 153;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 151;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,int,XmlFriendlyReplacer)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 155;
		bounds[1] = 161;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 159;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,NameCoder)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 163;
		bounds[1] = 168;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 166;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,XmlFriendlyReplacer)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 170;
		bounds[1] = 175;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 173;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer,int)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 177;
		bounds[1] = 182;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 180;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.PrettyPrintWriter(Writer)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 184;
		bounds[1] = 186;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 184;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.startNode(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 188;
		bounds[1] = 199;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 188;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.startNode(String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 201;
		bounds[1] = 203;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 201;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.setValue(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 205;
		bounds[1] = 211;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 205;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.addAttribute(String,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 213;
		bounds[1] = 220;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 213;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.writeAttributeValue(QuickWriter,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 222;
		bounds[1] = 224;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 222;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.writeText(QuickWriter,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 226;
		bounds[1] = 228;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 226;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.writeText(String,boolean)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 230;
		bounds[1] = 301;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 230;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.endNode()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 303;
		bounds[1] = 320;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 303;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.finishTag()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 322;
		bounds[1] = 332;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 322;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.endOfLine()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 334;
		bounds[1] = 339;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 334;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.flush()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 341;
		bounds[1] = 343;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 343;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.close()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 345;
		bounds[1] = 347;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 345;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "PrettyPrintWriter.getNewLine()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 349;
		bounds[1] = 351;
		bounds[2] = bounds[0] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 349;
		bounds[5] = bounds[4] - XSTREAM_PRETTYPRINTWRITER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//AnnotationConfiguration
		
		methodName = "AnnotationConfiguration.autodetectAnnotations(boolean)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 21;
		bounds[1] = 21;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONCONFIGURATION_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONCONFIGURATION_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 21;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONCONFIGURATION_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationConfiguration.processAnnotations(Class[])";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 23;
		bounds[1] = 23;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONCONFIGURATION_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONCONFIGURATION_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 23;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONCONFIGURATION_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//AnnotationMapper
		
		methodName = "AnnotationMapper.AnnotationMapper(Mapper,ConverterRegistry,ConverterLookup,ClassLoader,ReflectionProvider,JVM)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 71;
		bounds[1] = 92;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 77;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.realMember(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 95;
		bounds[1] = 100;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 95;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.serializedClass(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 103;
		bounds[1] = 108;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 103;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.defaultImplementationOf(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 111;
		bounds[1] = 120;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 111;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.getLocalConverter(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 123;
		bounds[1] = 128;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 123;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.autodetectAnnotations(boolean)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 130;
		bounds[1] = 132;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 130;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.processAnnotations(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 148;
		bounds[1] = 157;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 148;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.processTypes(Set<Class<?>>)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 159;
		bounds[1] = 203;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 159;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.addParametrizedTypes(Type,Set<Class<?>>)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 216;
		bounds[1] = 259;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 216;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.processConverterAnnotations(Class<?>)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 261;
		bounds[1] = 288;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 261;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.processAliasAnnotation(Class<?>,Set<Class<?>>)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 290;
		bounds[1] = 310;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 290;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.processImplicitCollectionAnnotation(Class<?>)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 313;
		bounds[1] = 351;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 313;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.processFieldAliasAnnotation(Field)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 353;
		bounds[1] = 364;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 353;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.processAsAttributeAnnotation(Field)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 366;
		bounds[1] = 377;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 366;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.processImplicitAnnotation(Field)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 379;
		bounds[1] = 418;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 379;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.processOmitFieldAnnotation(Field)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 420;
		bounds[1] = 431;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 420;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.processLocalConverterAnnotation(Field)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 433;
		bounds[1] = 447;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 433;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper.getClass(Type)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 520;
		bounds[1] = 528;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 520;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "AnnotationMapper$2.add(Class<?>)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 532;
		bounds[1] = 556;
		bounds[2] = bounds[0] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 532;
		bounds[5] = bounds[4] - XSTREAM_ANNOTATIONMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//ArrayMapper
		
		methodName = "ArrayMapper.ArrayMapper(Mapper)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 24;
		bounds[1] = 26;
		bounds[2] = bounds[0] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 24;
		bounds[5] = bounds[4] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ArrayMapper.serializedClass(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 28;
		bounds[1] = 52;
		bounds[2] = bounds[0] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 28;
		bounds[5] = bounds[4] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ArrayMapper.realClass(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 54;
		bounds[1] = 76;
		bounds[2] = bounds[0] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 54;
		bounds[5] = bounds[4] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ArrayMapper.arrayType(int,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 78;
		bounds[1] = 90;
		bounds[2] = bounds[0] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 78;
		bounds[5] = bounds[4] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ArrayMapper.boxedTypeName(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 92;
		bounds[1] = 94;
		bounds[2] = bounds[0] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 92;
		bounds[5] = bounds[4] - XSTREAM_ARRAYMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
				
		
		//ClassAliasingMapper
		
		methodName = "ClassAliasingMapper.ClassAliasingMapper(Mapper)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 32;
		bounds[1] = 34;
		bounds[2] = bounds[0] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 32;
		bounds[5] = bounds[4] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ClassAliasingMapper.addClassAlias(String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 36;
		bounds[1] = 39;
		bounds[2] = bounds[0] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 36;
		bounds[5] = bounds[4] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ClassAliasingMapper.addClassAttributeAlias(String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 41;
		bounds[1] = 46;
		bounds[2] = bounds[0] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 44;
		bounds[5] = bounds[4] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ClassAliasingMapper.addTypeAlias(String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 48;
		bounds[1] = 51;
		bounds[2] = bounds[0] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 48;
		bounds[5] = bounds[4] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ClassAliasingMapper.serializedClass(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 53;
		bounds[1] = 66;
		bounds[2] = bounds[0] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 53;
		bounds[5] = bounds[4] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ClassAliasingMapper.realClass(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 68;
		bounds[1] = 80;
		bounds[2] = bounds[0] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 68;
		bounds[5] = bounds[4] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ClassAliasingMapper.itemTypeAsAttribute(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 82;
		bounds[1] = 84;
		bounds[2] = bounds[0] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 82;
		bounds[5] = bounds[4] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ClassAliasingMapper.aliasIsAttribute(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 86;
		bounds[1] = 88;
		bounds[2] = bounds[0] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 86;
		bounds[5] = bounds[4] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "ClassAliasingMapper.readResolve()";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 90;
		bounds[1] = 101;
		bounds[2] = bounds[0] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 90;
		bounds[5] = bounds[4] - XSTREAM_CLASSALIASINGMAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		
		//MapperWrapper
		
		methodName = "MapperWrapper.MapperWrapper(Mapper)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 21;
		bounds[1] = 23;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 21;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.serializedClass(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 25;
		bounds[1] = 27;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 25;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.realClass(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 29;
		bounds[1] = 31;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 29;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.serializedMember(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 33;
		bounds[1] = 35;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 33;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.realMember(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 37;
		bounds[1] = 39;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 37;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.isImmutableValueType(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 41;
		bounds[1] = 43;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 41;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.defaultImplementationOf(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 45;
		bounds[1] = 47;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 45;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.aliasForAttribute(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 49;
		bounds[1] = 51;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 49;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.attributeForAlias(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 53;
		bounds[1] = 55;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 53;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.aliasForSystemAttribute(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 57;
		bounds[1] = 59;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 57;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.getFieldNameForItemTypeAndName(Class,Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 61;
		bounds[1] = 63;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 61;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.getItemTypeForItemFieldName(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 65;
		bounds[1] = 67;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 65;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.getImplicitCollectionDefForFieldName(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 69;
		bounds[1] = 71;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 69;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.shouldSerializeMember(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 73;
		bounds[1] = 75;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 73;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.getConverterFromItemType(String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 77;
		bounds[1] = 82;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 80;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.getConverterFromItemType(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 84;
		bounds[1] = 89;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 87;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.getConverterFromAttribute(String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 91;
		bounds[1] = 96;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 94;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.getLocalConverter(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 98;
		bounds[1] = 100;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 98;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.lookupMapperOfType(Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 102;
		bounds[1] = 104;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 102;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.getConverterFromItemType(String,Class,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 106;
		bounds[1] = 108;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 106;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.aliasForAttribute(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 110;
		bounds[1] = 115;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 113;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.attributeForAlias(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 117;
		bounds[1] = 122;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 120;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.getConverterFromAttribute(Class,String)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 124;
		bounds[1] = 129;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 127;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
		
		methodName = "MapperWrapper.getConverterFromAttribute(Class,String,Class)";
		bounds = new int[METHOD_BOUND_SIZE];
		bounds[0] = 131;
		bounds[1] = 133;
		bounds[2] = bounds[0] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[3] = bounds[1] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		bounds[4] = 131;
		bounds[5] = bounds[4] - XSTREAM_MAPPERWRAPPER_CLASS_EDITOR_NUMBER_DIFFERENCE;
		methods.put(methodName, bounds);
		xstreamMethodSequence.add(methodName);
				
		return methods;
	}
			
	private static Map<Integer,int[]> loadxstreamLines(){
		Map<Integer,int[]> lines = new HashMap<Integer,int[]>();
		int bounds[] = new int[LINE_BOUND_SIZE];
		int lineNumber = 0;
		
		lineNumber = 455;
		bounds[0] = 412;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 472;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 429;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 473;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 430;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 474;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 431;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 483;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 440;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 487;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 444;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 488;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 445;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 489;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 446;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 490;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 447;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 502;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 459;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 518;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 475;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 506;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 463;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 507;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 464;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 508;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 465;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 36;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 20;
		bounds[1] = 23;
		bounds[2] = 47;
		bounds[3] = 7;
		bounds[4] = 31;
		bounds[5] = 30;
		bounds[6] = 14;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 37;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 21;
		bounds[1] = 23;
		bounds[2] = 47;
		bounds[3] = 7;
		bounds[4] = 31;
		bounds[5] = 30;
		bounds[6] = 14;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 38;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 22;
		bounds[1] = 23;
		bounds[2] = 47;
		bounds[3] = 7;
		bounds[4] = 31;
		bounds[5] = 30;
		bounds[6] = 14;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 135;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 92;
		bounds[1] = 134;
		bounds[2] = 146;
		bounds[3] = 91;
		bounds[4] = 103;
		bounds[5] = 134;
		bounds[6] = 91;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 136;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 93;
		bounds[1] = 134;
		bounds[2] = 146;
		bounds[3] = 91;
		bounds[4] = 103;
		bounds[5] = 134;
		bounds[6] = 91;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 137;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 94;
		bounds[1] = 134;
		bounds[2] = 146;
		bounds[3] = 91;
		bounds[4] = 103;
		bounds[5] = 134;
		bounds[6] = 91;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 138;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 95;
		bounds[1] = 134;
		bounds[2] = 146;
		bounds[3] = 91;
		bounds[4] = 103;
		bounds[5] = 134;
		bounds[6] = 91;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 139;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 96;
		bounds[1] = 134;
		bounds[2] = 146;
		bounds[3] = 91;
		bounds[4] = 103;
		bounds[5] = 134;
		bounds[6] = 91;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 140;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 97;
		bounds[1] = 134;
		bounds[2] = 146;
		bounds[3] = 91;
		bounds[4] = 103;
		bounds[5] = 134;
		bounds[6] = 91;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 141;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 98;
		bounds[1] = 134;
		bounds[2] = 146;
		bounds[3] = 91;
		bounds[4] = 103;
		bounds[5] = 134;
		bounds[6] = 91;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 142;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 99;
		bounds[1] = 134;
		bounds[2] = 146;
		bounds[3] = 91;
		bounds[4] = 103;
		bounds[5] = 134;
		bounds[6] = 91;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 35;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 19;
		bounds[1] = 23;
		bounds[2] = 47;
		bounds[3] = 7;
		bounds[4] = 31;
		bounds[5] = 34;
		bounds[6] = 18;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 58;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 42;
		bounds[1] = 49;
		bounds[2] = 59;
		bounds[3] = 33;
		bounds[4] = 43;
		bounds[5] = 57;
		bounds[6] = 41;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 42;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 33;
		bounds[1] = 41;
		bounds[2] = 43;
		bounds[3] = 32;
		bounds[4] = 34;
		bounds[5] = 41;
		bounds[6] = 32;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 451;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 408;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 453;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 410;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 454;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 411;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 456;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 413;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 457;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 414;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 458;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 415;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 459;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 416;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 460;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 417;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 461;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 418;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 462;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 419;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 463;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 420;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 464;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 421;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 465;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 422;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 466;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 423;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 467;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 424;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 468;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 425;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 469;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 426;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 470;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 427;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 471;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 428;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		
		lineNumber = 475;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 432;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 476;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 433;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 477;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 434;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 479;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 436;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 480;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 437;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 481;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 438;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 482;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 439;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 484;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 441;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 485;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 442;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 486;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 443;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 492;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 449;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 496;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 453;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 499;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 456;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 501;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 458;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 503;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 460;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		 
		lineNumber = 505;
		bounds = new int[LINE_BOUND_SIZE];
		bounds[0] = 462;
		bounds[1] = 449;
		bounds[2] = 518;
		bounds[3] = 406;
		bounds[4] = 475;
		bounds[5] = 449;
		bounds[6] = 406;
		lines.put(lineNumber, bounds);
		xstreamLineSequence.add(String.valueOf(lineNumber));
		
		return lines;
	}
	
	public boolean editorActionIsInsideJSoupsInspectedMethod(String methodName, int clickedLine){
		int lines[] = jsoupMethods.get(methodName);
		if(lines != null){
			if(clickedLine >= lines[FIRSTLINE_METHOD_CLICK] && clickedLine <= lines[LASTLINE_METHOD_CLICK]){
				return true;
			}
		}
		return false;
	}
	
	public boolean jaguarActionIsInsideJSoupsInspectedMethod(String methodName, int clickedLine){
		int lines[] = jsoupMethods.get(methodName);
		if(lines != null){
			if(clickedLine >= lines[FIRSTLINE_METHOD_HOVER] && clickedLine <= lines[LASTLINE_METHOD_HOVER]){
				return true;
			}
		}
		return false;
	}
	
	public boolean editorActionIsInsideJSoupsInspectedLine(int lineNumber, int clickedLine){
		int lines[] = jsoupLines.get(lineNumber);
		if(lines != null){
			//System.out.println("Click: "+clickedLine +", lower: "+lines[FIRSTLINE_LINE_CLICK] +", higher: "+ lines[LASTLINE_LINE_CLICK]);
			if(clickedLine >= lines[FIRSTLINE_LINE_CLICK] && clickedLine <= lines[LASTLINE_LINE_CLICK]){
				return true;
			}
		}
		return false;
	}
	
	public boolean jaguarActionIsInsideJSoupsInspectedLine(int lineNumber, int clickedLine){
		int lines[] = jsoupLines.get(lineNumber);
		if(lines != null){
			if(clickedLine >= lines[FIRSTLINE_LINE_HOVER] && clickedLine <= lines[LASTLINE_LINE_HOVER]){
				return true;
			}
		}
		return false;
	}
	
	public boolean editorActionIsAfterJSoupsInspectedMethodSignature(String methodName, int clickedLine){
		int lines[] = jsoupMethods.get(methodName);
		if(lines != null){
			if(clickedLine >= lines[METHOD_SIGNATURE_CLICK]+1 && clickedLine <= lines[LASTLINE_METHOD_CLICK]){
				return true;
			}
		}
		return false;
	}
	
	public boolean jaguarActionIsAfterJSoupsInspectedMethodSignature(String methodName, int clickedLine){
		int lines[] = jsoupMethods.get(methodName);
		if(lines != null){
			if(clickedLine >= lines[METHOD_SIGNATURE_HOVER]+1 && clickedLine <= lines[LASTLINE_METHOD_HOVER]){
				return true;
			}
		}
		return false;
	}
	
	public boolean editorActionIsAfterJSoupsInspectedLineMethodSignature(int lineNumber, int clickedLine){
		int lines[] = jsoupLines.get(lineNumber);
		if(lines != null){
			if(clickedLine >= lines[METHOD_SIGNATURE_LINE_CLICK]+1 && clickedLine <= lines[LASTLINE_LINE_CLICK]){
				return true;
			}
		}
		return false;
	}
	
	public boolean jaguarActionIsAfterJSoupsInspectedLineMethodSignature(int lineNumber, int clickedLine){
		int lines[] = jsoupLines.get(lineNumber);
		if(lines != null){
			if(clickedLine >= lines[METHOD_SIGNATURE_LINE_HOVER]+1 && clickedLine <= lines[LASTLINE_LINE_HOVER]){
				return true;
			}
		}
		return false;
	}
	
	public boolean editorActionIsInsideXStreamsInspectedMethod(String methodName, int clickedLine){
		int lines[] = xstreamMethods.get(methodName);
		if(lines != null){
			if(clickedLine >= lines[FIRSTLINE_METHOD_CLICK] && clickedLine <= lines[LASTLINE_METHOD_CLICK]){
				return true;
			}
		}
		return false;
	}
	
	public boolean jaguarActionIsInsideXStreamsInspectedMethod(String methodName, int clickedLine){
		int lines[] = xstreamMethods.get(methodName);
		if(lines != null){
			if(clickedLine >= lines[FIRSTLINE_METHOD_HOVER] && clickedLine <= lines[LASTLINE_METHOD_HOVER]){
				return true;
			}
		}
		return false;
	}
	
	
	public boolean editorActionIsInsideXStreamsInspectedLine(int lineNumber, int clickedLine){
		int lines[] = xstreamLines.get(lineNumber);
		if(lines != null){
			if(clickedLine >= lines[FIRSTLINE_LINE_CLICK] && clickedLine <= lines[LASTLINE_LINE_CLICK]){
				return true;
			}
		}
		return false;
	}
	
	public boolean jaguarActionIsInsideXStreamsInspectedLine(int lineNumber, int clickedLine){
		int lines[] = xstreamLines.get(lineNumber);
		if(lines != null){
			if(clickedLine >= lines[FIRSTLINE_LINE_HOVER] && clickedLine <= lines[LASTLINE_LINE_HOVER]){
				return true;
			}
		}
		return false;
	}
	
	public boolean editorActionIsAfterXStreamsInspectedMethodSignature(String methodName, int clickedLine){
		int lines[] = xstreamMethods.get(methodName);
		if(lines != null){
			if(clickedLine >= lines[METHOD_SIGNATURE_CLICK]+1 && clickedLine <= lines[LASTLINE_METHOD_CLICK]){
				return true;
			}
		}
		return false;
	}
	
	public boolean jaguarActionIsAfterXStreamsInspectedMethodSignature(String methodName, int clickedLine){
		int lines[] = xstreamMethods.get(methodName);
		if(lines != null){
			if(clickedLine >= lines[METHOD_SIGNATURE_HOVER]+1 && clickedLine <= lines[LASTLINE_METHOD_HOVER]){
				return true;
			}
		}
		return false;
	}
	
	
	public boolean editorActionIsAfterXStreamsInspectedLineMethodSignature(int lineNumber, int clickedLine){
		int lines[] = xstreamLines.get(lineNumber);
		if(lines != null){
			if(clickedLine >= lines[METHOD_SIGNATURE_LINE_CLICK]+1 && clickedLine <= lines[LASTLINE_LINE_CLICK]){
				return true;
			}
		}
		return false;
	}
	
	public boolean jaguarActionIsAfterXStreamsInspectedLineMethodSignature(int lineNumber, int clickedLine){
		int lines[] = xstreamLines.get(lineNumber);
		if(lines != null){
			if(clickedLine >= lines[METHOD_SIGNATURE_LINE_HOVER]+1 && clickedLine <= lines[LASTLINE_LINE_HOVER]){
				return true;
			}
		}
		return false;
	}
	
	public boolean isJSoupsFailedTestClass(String className){
		if(className.equals(JSOUP_FAILED_TESTCLASS)){
			return true;
		}
		return false;
	}

	public boolean isXStreamsFailedTestClass(String className){
		if(className.equals(XSTREAM_FAILED_TESTCLASS)){
			return true;
		}
		return false;
	}
	
	public boolean clickOnJSoupsFaultyMethod(String classAndMethodName){
		if(classAndMethodName.equals(JSOUP_FAULTY_METHOD)){
			return true;
		}
		return false;
	}
	
	public boolean clickOnJSoupsFaultyLine(String lineNumber){
		if(lineNumber.equals(JSOUP_FAULTY_LINE)){
			return true;
		}
		return false;
	}
	
	public boolean clickOnJSoupsFaultyLineOnEditor(String lineNumber){
		if(lineNumber.equals(JSOUP_FAULTY_LINE_ON_EDITOR)){
			return true;
		}
		return false;
	}
	
	public boolean isJSoupsFaultyCode(String code){
		if(code.equals(JSOUP_FAULTY_CODE)){
			return true;
		}
		return false;
	}
	
	public boolean containsJSoupsFaultyCode(String code){
		if(code.contains(JSOUP_FAULTY_CODE_CHUNK)){
			return true;
		}
		return false;
	}
	
	public boolean isJSoupsFaultyClass(String classname){
		if(classname.equals(JSOUP_FAULTY_CLASS)){
			return true;
		}
		return false;
	}
	
	public boolean clickOnXStreamsFaultyMethod(String classAndMethodName){
		if(classAndMethodName.equals(XSTREAM_FAULTY_METHOD)){
			return true;
		}
		return false;
	}
	
	public boolean clickOnXStreamsFaultyLine(String lineNumber){
		if(lineNumber.equals(XSTREAM_FAULTY_LINE)){
			return true;
		}
		return false;
	}
	
	public boolean clickOnXStreamsFaultyLineOnEditor(String lineNumber){
		if(lineNumber.equals(XSTREAM_FAULTY_LINE_ON_EDITOR)){
			return true;
		}
		return false;
	}
	
	public boolean isXStreamsFaultyCode(String code){
		if(code.equals(XSTREAM_FAULTY_CODE)){
			return true;
		}
		return false;
	}
	
	public boolean containsXStreamsFaultyCode(String code){
		if(code.contains(XSTREAM_FAULTY_CODE_CHUNK)){
			return true;
		}
		return false;
	}
	
	public boolean isXStreamsFaultyClass(String classname){
		if(classname.equals(XSTREAM_FAULTY_CLASS)){
			return true;
		}
		return false;
	}
	
	public boolean lineBelongsToAnyJSoupMethodInJaguar(String className, int inspectedLine){
		Set<String> methods = jsoupMethods.keySet();
		for(String method : methods){
			if(method.startsWith(className)){
				int methodLines[] = jsoupMethods.get(method);
				if(inspectedLine > methodLines[METHOD_SIGNATURE_HOVER] && inspectedLine <= methodLines[LASTLINE_METHOD_HOVER]){
					return true;
				}
			}
		}
		return false;
	}
	
	public boolean lineBelongsToAnyXStreamMethodInJaguar(String className, int inspectedLine){
		Set<String> methods = xstreamMethods.keySet();
		for(String method : methods){
			if(method.startsWith(className)){
				int methodLines[] = xstreamMethods.get(method);
				if(inspectedLine > methodLines[METHOD_SIGNATURE_HOVER] && inspectedLine <= methodLines[LASTLINE_METHOD_HOVER]){
					return true;
				}
			}
		}
		return false;
	}
	
	public boolean lineBelongsToAnyJSoupLineInJaguar(int inspectedLine){
		Set<Integer> lines = jsoupLines.keySet();
		for(int line : lines){
			if(line == inspectedLine){
				return true;
			}
		}
		return false;
	}
	
	public boolean lineBelongsToAnyXStreamLineInJaguar(int inspectedLine){
		Set<Integer> lines = xstreamLines.keySet();
		for(int line : lines){
			if(line == inspectedLine){
				return true;
			}
		}
		return false;
	}
	
	
	public boolean lineBelongsToJSoupsFaultyMethod(String className, int inspectedLine){
		int methodLines[] = jsoupMethods.get(JSOUP_FAULTY_METHOD);
		if(JSOUP_FAULTY_METHOD.startsWith(className)){
			if(inspectedLine > methodLines[METHOD_SIGNATURE_HOVER] && inspectedLine <= methodLines[LASTLINE_METHOD_HOVER]){
				return true;
			}
		}
		return false;
	}
	
	public boolean lineBelongsToXStreamsFaultyMethod(String className, int inspectedLine){
		int methodLines[] = xstreamMethods.get(XSTREAM_FAULTY_METHOD);
		if(XSTREAM_FAULTY_METHOD.startsWith(className)){
			if(inspectedLine > methodLines[METHOD_SIGNATURE_HOVER] && inspectedLine <= methodLines[LASTLINE_METHOD_HOVER]){
				return true;
			}
		}
		return false;
	}
	
	
	public String getJSoupMethodInEclipse(String className, int inspectedLine){
		Set<String> methods = jsoupMethods.keySet();
		for(String method : methods){
			if(method.startsWith(className)){
				int methodLines[] = jsoupMethods.get(method);
				if(inspectedLine > methodLines[FIRSTLINE_METHOD_CLICK] && inspectedLine <= methodLines[LASTLINE_METHOD_CLICK]){
					return method;
				}
			}
		}
		return "";
	}
	
	public String getXStreamMethodInEclipse(String className, int inspectedLine){
		Set<String> methods = xstreamMethods.keySet();
		for(String method : methods){
			if(method.startsWith(className)){
				int methodLines[] = xstreamMethods.get(method);
				if(inspectedLine > methodLines[FIRSTLINE_METHOD_CLICK] && inspectedLine <= methodLines[LASTLINE_METHOD_CLICK]){
					return method;
				}
			}
		}
		return "";
	}
	
	
	public boolean lineBelongsToAnyJSoupMethodInJaguarUsingEditor(String className, int inspectedLine){
		Set<String> methods = jsoupMethods.keySet();
		for(String method : methods){
			if(method.startsWith(className)){
				int methodLines[] = jsoupMethods.get(method);
				if(inspectedLine > methodLines[FIRSTLINE_METHOD_CLICK] && inspectedLine <= methodLines[LASTLINE_METHOD_CLICK]){
					return true;
				}
			}
		}
		return false;
	}
	
	public boolean lineBelongsToAnyXStreamMethodInJaguarUsingEditor(String className, int inspectedLine){
		Set<String> methods = xstreamMethods.keySet();
		for(String method : methods){
			if(method.startsWith(className)){
				int methodLines[] = xstreamMethods.get(method);
				if(inspectedLine > methodLines[FIRSTLINE_METHOD_CLICK] && inspectedLine <= methodLines[LASTLINE_METHOD_CLICK]){
					return true;
				}
			}
		}
		return false;
	}
	

	public List<String> getJSoupsMethodSequence(){
		return jsoupMethodSequence;
	}
	
	public List<String> getJSoupsLineSequence(){
		return jsoupLineSequence;
	}
	
	public List<String> getXStreamsMethodSequence(){
		return xstreamMethodSequence;
	}
	
	public List<String> getXStreamsLineSequence(){
		return xstreamLineSequence;
	}
	
	
}