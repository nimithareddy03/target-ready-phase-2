package com.fscan.File.Scanner.service;

import com.fscan.File.Scanner.APIconnector.VirusTotal;
import com.fscan.File.Scanner.FileAuditDTO.FileAuditDTO;
import com.fscan.File.Scanner.entity.FileAudit;
import com.fscan.File.Scanner.exception.AnalysisIdNotFoundException;
import com.fscan.File.Scanner.exception.FileAccessException;
import com.fscan.File.Scanner.exception.ScanningUnderProgressException;
import com.fscan.File.Scanner.service.FileAuditService;
import com.fscan.File.Scanner.serviceImplementation.FileControllerServiceImpl;
import com.fscan.File.Scanner.utils.Validators;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MultipartFile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

public class FileControllerServiceTest {

    @Mock
    private FileAuditService fileAuditService;

    @Mock
    private VirusTotal virusTotal;

    @Mock
    private Validators validators;

    @InjectMocks
    private FileControllerServiceImpl fileControllerServiceImpl;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testFileHandlerService() throws FileAccessException, ScanningUnderProgressException {
        // Mock MultipartFile
        MultipartFile file = mock(MultipartFile.class);
        when(file.getOriginalFilename()).thenReturn("testfile.txt");

        // Mock FileAuditService.save()
        FileAuditDTO fileAuditDTO = new FileAuditDTO();
        fileAuditDTO.setId(1L);
        when(fileAuditService.save("testfile.txt", "File uploaded to DB")).thenReturn(fileAuditDTO);

        // Mock VirusTotal.ScanByFile()
        when(virusTotal.ScanByFile(eq(file), eq(fileAuditService), eq(1L))).thenReturn("Scan Successful");

        // Call method
        ResponseEntity<String> response = fileControllerServiceImpl.FileHandlerService(file);

        // Verify and assert
        verify(fileAuditService, times(1)).save("testfile.txt", "File uploaded to DB");
        verify(virusTotal, times(1)).ScanByFile(file, fileAuditService, 1L);
        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertEquals("Scan Successful", response.getBody());
    }

    @Test
    public void testAnalysisIdHandlerService() throws AnalysisIdNotFoundException, ScanningUnderProgressException {
        // Mock FileAuditService.findByAnalysisId()
        FileAudit fileAudit = new FileAudit();
        fileAudit.setId(1L);
        when(fileAuditService.findByAnalysisId("12345")).thenReturn(fileAudit);

        // Mock VirusTotal.ScanByAnalysisId()
        when(virusTotal.ScanByAnalysisId(eq("12345"), eq(fileAuditService), eq(1L))).thenReturn("Scan Successful");

        // Call method
        ResponseEntity<String> response = fileControllerServiceImpl.AnalysisIdHandlerService("12345");

        // Verify and assert
        verify(fileAuditService, times(1)).findByAnalysisId("12345");
        verify(virusTotal, times(1)).ScanByAnalysisId("12345", fileAuditService, 1L);
        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertEquals("Scan Successful", response.getBody());
    }
}
