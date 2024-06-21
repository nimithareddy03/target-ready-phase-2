package com.fscan.File.Scanner.controller;

import com.fscan.File.Scanner.exception.AnalysisIdNotFoundException;
import com.fscan.File.Scanner.exception.FileAccessException;
import com.fscan.File.Scanner.exception.ScanningUnderProgressException;
import com.fscan.File.Scanner.service.FileControllerService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

public class FileControllerTest {

    @Mock
    private FileControllerService fileControllerService;

    @InjectMocks
    private FileController fileController;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testFileHandler() throws FileAccessException, ScanningUnderProgressException {
        // Create a mock MultipartFile
        MultipartFile file = new MockMultipartFile("file", "filename.txt", "text/plain", "some xml".getBytes());

        // Set up the expected response
        ResponseEntity<String> expectedResponse = ResponseEntity.status(HttpStatus.ACCEPTED).body("File processed successfully");
        when(fileControllerService.FileHandlerService(file)).thenReturn(expectedResponse);

        // Call the method under test
        ResponseEntity<String> actualResponse = fileController.fileHandler(file);

        // Validate the response
        assertEquals(expectedResponse, actualResponse);
        verify(fileControllerService).FileHandlerService(file);
    }

    @Test
    public void testIdHandler() throws AnalysisIdNotFoundException, ScanningUnderProgressException {
        // Setup the expected ID and response
        String id = "12345";
        ResponseEntity<String> expectedResponse = ResponseEntity.status(HttpStatus.ACCEPTED).body("Analysis complete");
        when(fileControllerService.AnalysisIdHandlerService(id)).thenReturn(expectedResponse);

        // Call the method under test
        ResponseEntity<String> actualResponse = fileController.IdHandler(id);

        // Validate the response
        assertEquals(expectedResponse, actualResponse);
        verify(fileControllerService).AnalysisIdHandlerService(id);
    }
}
