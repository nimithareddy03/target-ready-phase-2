package com.fscan.File.Scanner.service;

import com.fscan.File.Scanner.APIconnector.VirusTotal;
import com.fscan.File.Scanner.FileAuditDTO.FileAuditDTO;
import com.fscan.File.Scanner.entity.FileAudit;
import com.fscan.File.Scanner.exception.AnalysisIdNotFoundException;
import com.fscan.File.Scanner.exception.FileAccessException;
import com.fscan.File.Scanner.exception.ScanningUnderProgressException;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class FileControllerServiceTest {

    @Mock
    private MultipartFile file;

    @Mock
    private FileAuditService fileAuditService;

    @Mock
    private VirusTotal virusTotal;

    @Mock
    private Validators validators;

    @InjectMocks
    private FileControllerServiceImpl fileControllerServiceImpl;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testFileHandlerService() throws FileAccessException, ScanningUnderProgressException {
        // Arrange
        FileAuditDTO fileAuditDTO = new FileAuditDTO();
        fileAuditDTO.setId(1L);
        when(file.getOriginalFilename()).thenReturn("testFile.txt");
        when(fileAuditService.save(anyString(), anyString())).thenReturn(fileAuditDTO);
        when(virusTotal.ScanByFile(any(MultipartFile.class), any(FileAuditService.class), anyLong())).thenReturn("scanResponse");
        when(validators.isValidResult(anyString())).thenReturn(true);
        when(validators.FinalizeVerdict(anyString())).thenReturn("scanResults");

        // Act
        ResponseEntity<String> response = fileControllerServiceImpl.FileHandlerService(file);

        // Assert
        assertEquals("scanResults", response.getBody());
        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        verify(fileAuditService, times(1)).save("testFile.txt", "File uploaded to DB");
        verify(fileAuditService, times(1)).updateScanResults(1L, "scanResults");
        verify(fileAuditService, times(1)).updateDT(1L);
    }

    @Test
    void testAnalysisIdHandlerServiceSuccess() throws AnalysisIdNotFoundException, ScanningUnderProgressException {
        // Arrange
        FileAudit fileAudit = new FileAudit();
        fileAudit.setId(1L);
        when(fileAuditService.findByAnalysisId(anyString())).thenReturn(fileAudit);
        when(virusTotal.ScanByAnalysisId(anyString(), any(FileAuditService.class), anyLong())).thenReturn("scanResponse");
        when(validators.isValidResult(anyString())).thenReturn(true);
        when(validators.FinalizeVerdict(anyString())).thenReturn("scanResults");

        // Act
        ResponseEntity<String> response = fileControllerServiceImpl.AnalysisIdHandlerService("123");

        // Assert
        assertEquals("scanResults", response.getBody());
        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        verify(fileAuditService, times(1)).findByAnalysisId("123");
        verify(fileAuditService, times(1)).updateScanResults(1L, "scanResults");
        verify(fileAuditService, times(1)).updateDT(1L);
    }
}
