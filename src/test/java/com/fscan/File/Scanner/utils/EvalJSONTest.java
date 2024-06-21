package com.fscan.File.Scanner.utils;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;

public class EvalJSONTest {

    @InjectMocks
    private EvalJSON evalJSON;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testTextToJSON() {
        String jsonString = "{\"key\":\"value\"}";
        JSONObject jsonObject = evalJSON.TextToJSON(jsonString);
        assertNotNull(jsonObject);
        assertEquals("value", jsonObject.get("key"));
    }

    @Test
    public void testAnalysisStats_Found() {
        String response = "{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"harmless\":5,\"malicious\":1}}}}";
        String result = evalJSON.analysisStats(response);
        try {
            JSONObject expectedJson = new JSONObject("{\"harmless\":5,\"malicious\":1}");
            JSONObject actualJson = new JSONObject(result);
            assertEquals(expectedJson.toString(), actualJson.toString());
        } catch (JSONException e) {
            fail("Invalid JSON format");
        }
    }

    @Test
    public void testAnalysisStats_NotFound() {
        String response = "{\"data\":{\"attributes\":{}}}";
        String result = evalJSON.analysisStats(response);
        assertEquals("NotFoundError", result);
    }

    @Test
    public void testAnalysisId_Found() {
        String response = "{\"data\":{\"id\":\"12345\"}}";
        String result = evalJSON.analysisId(response);
        assertEquals("12345", result);
    }

    @Test
    public void testAnalysisId_NotFound() {
        String response = "{\"data\":{}}";
        String result = evalJSON.analysisId(response);
        assertTrue(result.contains("JSONException"));
    }

    @Test
    public void testStatsByAId_Found() {
        String response = "{\"data\":{\"attributes\":{\"stats\":{\"scanned\":10}}}}";
        String result = evalJSON.StatsByAId(response);
        try {
            JSONObject expectedJson = new JSONObject("{\"scanned\":10}");
            JSONObject actualJson = new JSONObject(result);
            assertEquals(expectedJson.toString(), actualJson.toString());
        } catch (JSONException e) {
            fail("Invalid JSON format");
        }
    }

    @Test
    public void testStatsByAId_NotFound() {
        String response = "{\"data\":{\"attributes\":{}}}";
        String result = evalJSON.StatsByAId(response);
        assertTrue(result.contains("one the following key is missing"));
    }

    @Test
    public void testStatus_Found() {
        String response = "{\"data\":{\"attributes\":{\"status\":\"completed\"}}}";
        String result = evalJSON.Status(response);
        assertEquals("completed", result);
    }

    @Test
    public void testStatus_NotFound() {
        String response = "{\"data\":{\"attributes\":{}}}";
        String result = evalJSON.Status(response);
        assertTrue(result.contains("one the following key is missing"));
    }

    @Test
    public void testMalwareDetailsFromAnalysisIdResponse_Found() {
        String response = "{\"data\":{\"attributes\":{\"results\":{\"vendor1\":{\"category\":\"malicious\",\"result\":\"malware1\"},\"vendor2\":{\"category\":\"clean\"}}}}}";
        JSONObject result = evalJSON.MalwareDetailsFromAnalysisIdResponse(response);
        assertNotNull(result);
        assertEquals("malware1", result.get("vendor1"));
        assertFalse(result.has("vendor2"));
    }

    @Test
    public void testMalwareDetailsFromAnalysisIdResponse_NotFound() {
        String response = "{\"data\":{\"attributes\":{}}}";
        JSONObject result = evalJSON.MalwareDetailsFromAnalysisIdResponse(response);
        assertNull(result);
    }

    @Test
    public void testMalwareDetailsFromHexResponse_Found() {
        String response = "{\"data\":{\"attributes\":{\"last_analysis_results\":{\"vendor1\":{\"category\":\"malicious\",\"result\":\"malware1\"},\"vendor2\":{\"category\":\"clean\"}}}}}";
        JSONObject result = evalJSON.MalwareDetailsFromHexResponse(response);
        assertNotNull(result);
        assertEquals("malware1", result.get("vendor1"));
        assertFalse(result.has("vendor2"));
    }

    @Test
    public void testMalwareDetailsFromHexResponse_NotFound() {
        String response = "{\"data\":{\"attributes\":{}}}";
        JSONObject result = evalJSON.MalwareDetailsFromHexResponse(response);
        assertNull(result);
    }
}
