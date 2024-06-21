package com.fscan.File.Scanner.utils;

import com.fscan.File.Scanner.exception.ScanningUnderProgressException;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class ValidatorsTest {

    @Mock
    private EvalJSON evalJSON;

    @InjectMocks
    private Validators validators;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testIsAnalyisId_Valid() {
        String analysisId = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdabcdefefpqrstuvwxyz123456789==";
        assertTrue(validators.IsAnalyisId(analysisId));
    }

    @Test
    public void testIsAnalyisId_InvalidLength() {
        String analysisId = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=";
        assertFalse(validators.IsAnalyisId(analysisId));
    }


    @Test
    public void testIsAnalyisId_InvalidEnding() {
        String analysisId = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!=";
        assertFalse(validators.IsAnalyisId(analysisId));
    }

    @Test
    public void testIsAnalyisId_Invalid() {
        String analysisId = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=!";
        assertFalse(validators.IsAnalyisId(analysisId));
    }

    @Test
    public void testIsValidResponse_Completed() {
        String response = "{\"data\":{\"attributes\":{\"status\":\"completed\"}}}";
        when(evalJSON.Status(response)).thenReturn("completed");
        assertTrue(validators.IsValidResponse(response));
    }

    @Test
    public void testIsValidResponse_Incomplete() {
        String response = "{\"data\":{\"attributes\":{\"status\":\"incomplete\"}}}";
        when(evalJSON.Status(response)).thenReturn("incomplete");
        assertFalse(validators.IsValidResponse(response));
    }

    @Test
    public void testIsValidResult_Valid() throws ScanningUnderProgressException {
        String result = "{\"malicious\":1,\"undetected\":58,\"harmless\":0,\"suspicious\":0}";
        JSONObject jsonObject = new JSONObject(result);
        when(evalJSON.TextToJSON(result)).thenReturn(jsonObject);

        boolean isValid = validators.isValidResult(result);

        assertTrue(isValid);
        verify(evalJSON, times(1)).TextToJSON(result);
    }

    @Test
    public void testIsValidResult_ScanningUnderProgressException() {
        String result = "{\"malicious\":0,\"undetected\":0,\"harmless\":0,\"suspicious\":0}";
        JSONObject jsonObject = new JSONObject(result);
        when(evalJSON.TextToJSON(result)).thenReturn(jsonObject);

        ScanningUnderProgressException exception = assertThrows(ScanningUnderProgressException.class, () -> {
            validators.isValidResult(result);
        });

        assertNotNull(exception);
        verify(evalJSON, times(1)).TextToJSON(result);
    }

    @Test
    public void testIsValidResult_Invalid() throws ScanningUnderProgressException {
        String result = "{\"type-unsupported\":15,\"failure\":0,\"confirmed-timeout\":0,\"timeout\":0}";

        boolean isValid = validators.isValidResult(result);

        assertFalse(isValid);
        verify(evalJSON, never()).TextToJSON(anyString());
    }

    @Test
    public void testFinalizeVerdict_Malicious() {
        String result = "{\"malicious\":1,\"suspicious\":0}";
        when(evalJSON.TextToJSON(result)).thenReturn(new JSONObject(result));
        String verdict = validators.FinalizeVerdict(result);
        assertEquals("Malicious", verdict);
    }

    @Test
    public void testFinalizeVerdict_Suspicious() {
        String result = "{\"malicious\":0,\"suspicious\":1}";
        when(evalJSON.TextToJSON(result)).thenReturn(new JSONObject(result));
        String verdict = validators.FinalizeVerdict(result);
        assertEquals("Suspicious", verdict);
    }

    @Test
    public void testFinalizeVerdict_NoMalwareFound() {
        String result = "{\"malicious\":0,\"suspicious\":0}";
        when(evalJSON.TextToJSON(result)).thenReturn(new JSONObject(result));
        String verdict = validators.FinalizeVerdict(result);
        assertEquals("No Malware Found", verdict);
    }
}
