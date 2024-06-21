package com.fscan.File.Scanner.APIconnector;

import com.fscan.File.Scanner.exception.FileAccessException;
import com.fscan.File.Scanner.exception.ScanningUnderProgressException;
import com.fscan.File.Scanner.service.FileAuditService;
import com.fscan.File.Scanner.utils.EvalJSON;
import com.fscan.File.Scanner.utils.Validators;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class VirusTotalTest {

    @InjectMocks
    private VirusTotal virusTotal;

    @Mock
    private Validators validators;

    @Mock
    private EvalJSON evalJSON;

    @Mock
    private FileAuditService fileAuditService;

    @Mock
    private RestTemplate restTemplate;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testShaGenerator() throws IOException {
        byte[] fileContents = "sample content".getBytes(StandardCharsets.UTF_8);
        String sha = virusTotal.ShaGenerator(fileContents);
        assertNotNull(sha);
        assertEquals(64, sha.length()); // SHA-256 produces 64 hex characters
    }

    @Test
    void testScanByHex() {
        String hexCode = "someHexCode";
        String url = "url-scan-hex" + hexCode;
        HttpHeaders headers = new HttpHeaders();
        headers.set("x-apikey", "API-KEY");
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

        ResponseEntity<String> response = new ResponseEntity<>("{ \"result\": \"scan result\" }", HttpStatus.OK);
        when(restTemplate.exchange(eq(url), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class))).thenReturn(response);

        String result = virusTotal.ScanByHex(hexCode);
        assertNotNull(result);
        assertEquals("{ \"result\": \"scan result\" }", result);
    }

    @Test
    void testUploadFile() throws IOException, FileAccessException {
        MultipartFile multipartFile = new MockMultipartFile("file", "test.txt", "text/plain", "sample content".getBytes(StandardCharsets.UTF_8));

        HttpHeaders headers = new HttpHeaders();
        headers.set("x-apikey", "API-KEY");
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new ByteArrayResource("sample content".getBytes(StandardCharsets.UTF_8)) {
            @Override
            public String getFilename() {
                return "test.txt";
            }
        });

        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);

        ResponseEntity<String> response = new ResponseEntity<>("{ \"analysis_id\": \"1234\" }", HttpStatus.OK);
        when(restTemplate.postForEntity("url-upload", requestEntity, String.class)).thenReturn(response);

        when(evalJSON.analysisId("{ \"analysis_id\": \"1234\" }")).thenReturn("1234");

        String result = virusTotal.UploadFile(multipartFile);
        assertEquals("1234", result);
    }

    @Test
    void testScanByAnalysisId() {
        String analysisID = "analysisID";
        Long id = 1L;
        String url = "url-scan-id" + analysisID;

        HttpHeaders headers = new HttpHeaders();
        headers.set("x-apikey", "API-KEY");
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

        ResponseEntity<String> response = new ResponseEntity<>("{ \"result\": \"scan result\" }", HttpStatus.OK);
        when(restTemplate.exchange(eq(url), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class))).thenReturn(response);

        when(validators.IsValidResponse("{ \"result\": \"scan result\" }")).thenReturn(true);
        when(evalJSON.StatsByAId("{ \"result\": \"scan result\" }")).thenReturn("Malicious");
        when(validators.FinalizeVerdict("Malicious")).thenReturn("Malicious");

        JSONObject malwareDetails = new JSONObject();
        malwareDetails.put("type", "malware");
        when(evalJSON.MalwareDetailsFromAnalysisIdResponse("{ \"result\": \"scan result\" }")).thenReturn(malwareDetails);

        String result = virusTotal.ScanByAnalysisId(analysisID, fileAuditService, id);
        assertNotNull(result);
        assertTrue(result.contains("Malicious"));
        assertTrue(result.contains("malware"));
    }

    @Test
    void testScanByFile() throws IOException, FileAccessException, ScanningUnderProgressException {
        MultipartFile file = new MockMultipartFile("file", "test.txt", "text/plain", "sample content".getBytes(StandardCharsets.UTF_8));
        Long id = 1L;

        when(validators.isValidResult(any())).thenReturn(true);
        when(evalJSON.analysisStats(any())).thenReturn("Malicious");
        when(validators.FinalizeVerdict(any())).thenReturn("Malicious");

        JSONObject malwareDetails = new JSONObject();
        malwareDetails.put("type", "malware");
        when(evalJSON.MalwareDetailsFromHexResponse(any())).thenReturn(malwareDetails);

        String result = virusTotal.ScanByFile(file, fileAuditService, id);
        assertNotNull(result);
    }
}