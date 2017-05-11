package br.usp.each.saeg.loganalyzer;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class SuspiciousCodeTest {

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void jsoupClickingOnFaultyMethodTest() {
		SuspiciousCode susp = new SuspiciousCode();
		assertTrue(susp.editorActionIsInsideJSoupsInspectedMethod("Element.indexInList(Element,Index<E>)", 565));
	}
	
	@Test
	public void jsoupHoveringOnFaultyMethodTest() {
		SuspiciousCode susp = new SuspiciousCode();
		assertTrue(susp.jaguarActionIsInsideJSoupsInspectedMethod("Element.indexInList(Element,Index<E>)", 573));
	}
	
	@Test
	public void jsoupClickingOnFaultyLineTest() {
		SuspiciousCode susp = new SuspiciousCode();
		assertTrue(susp.editorActionIsInsideJSoupsInspectedLine(574,565));
	}
	
	@Test
	public void jsoupHoveringOnFaultyLineTest() {
		SuspiciousCode susp = new SuspiciousCode();
		assertTrue(susp.jaguarActionIsInsideJSoupsInspectedLine(574,575));
	}

	@Test
	public void xstreamClickingOnFaultyMethodTest() {
		SuspiciousCode susp = new SuspiciousCode();
		assertTrue(susp.editorActionIsInsideXStreamsInspectedMethod("AnnotationMapper.cacheConverter(XStreamConverter,Class)", 411));
	}
	
	@Test
	public void xstreamHoveringOnFaultyMethodTest() {
		SuspiciousCode susp = new SuspiciousCode();
		assertTrue(susp.jaguarActionIsInsideXStreamsInspectedMethod("AnnotationMapper.cacheConverter(XStreamConverter,Class)", 454));
	}
	
	@Test
	public void xstreamClickingOnFaultyLineTest() {
		SuspiciousCode susp = new SuspiciousCode();
		assertTrue(susp.editorActionIsInsideXStreamsInspectedLine(454,475));
	}

	@Test
	public void xstreamHoveringOnFaultyLineTest() {
		SuspiciousCode susp = new SuspiciousCode();
		assertTrue(susp.jaguarActionIsInsideXStreamsInspectedLine(454,518));
	}
	
	@Test
	public void jsoupMethodNameFromEditorClickTest() {
		SuspiciousCode susp = new SuspiciousCode();
		assertTrue("Element.indexInList(Element,Index<E>)".equals(susp.getJSoupMethodInEclipse("Element", 566)));
	}
	

}
