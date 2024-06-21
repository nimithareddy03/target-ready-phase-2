package com.fscan.File.Scanner.service;

import com.fscan.File.Scanner.FileAuditDTO.FileAuditDTO;
import com.fscan.File.Scanner.entity.FileAudit;
import com.fscan.File.Scanner.exception.AnalysisIdNotFoundException;
import com.fscan.File.Scanner.repository.FileAuditRepo;
import com.fscan.File.Scanner.serviceImplementation.FileAuditServiceImpl;
import com.fscan.File.Scanner.serviceImplementation.FileControllerServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class FileAuditServiceTest {

    @InjectMocks
    private FileAuditServiceImpl fileAuditService;

    @Mock
    private FileAuditRepo fileAuditRepository;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testSave() {
        String fileName = "test.txt";
        String status = "Pending";
        FileAudit fileAudit = new FileAudit();
        fileAudit.setFileName(fileName);
        fileAudit.setStatus(status);

        when(fileAuditRepository.save(any(FileAudit.class))).thenReturn(fileAudit);

        FileAuditDTO result = fileAuditService.save(fileName, status);

        assertNotNull(result);
        assertEquals(fileName, result.getFileName());
        assertEquals(status, result.getStatus());
    }


    @Test
    void testUpdateStatus() {
        Long id = 1L;
        String status = "Completed";
        FileAudit fileAudit = new FileAudit();
        fileAudit.setId(id);
        fileAudit.setStatus("Pending");

        when(fileAuditRepository.findById(id)).thenReturn(Optional.of(fileAudit));

        fileAuditService.updateStatus(id, status);

        verify(fileAuditRepository, times(1)).save(fileAudit);
        assertEquals(status, fileAudit.getStatus());
    }

    @Test
    void testUpdateSHA256() {
        Long id = 1L;
        String hexcode = "abcdef123456";
        FileAudit fileAudit = new FileAudit();
        fileAudit.setId(id);

        when(fileAuditRepository.findById(id)).thenReturn(Optional.of(fileAudit));

        fileAuditService.updateSHA256(id, hexcode);

        verify(fileAuditRepository, times(1)).save(fileAudit);
        assertEquals(hexcode, fileAudit.getSHA256());
    }

    @Test
    void testUpdateAID() {
        Long id = 1L;
        String AID = "AID123456";
        FileAudit fileAudit = new FileAudit();
        fileAudit.setId(id);

        when(fileAuditRepository.findById(id)).thenReturn(Optional.of(fileAudit));

        fileAuditService.updateAID(id, AID);

        verify(fileAuditRepository, times(1)).save(fileAudit);
        assertEquals(AID, fileAudit.getAnalysisId());
    }

    @Test
    void testUpdateDT() {
        Long id = 1L;
        FileAudit fileAudit = new FileAudit();
        fileAudit.setId(id);

        when(fileAuditRepository.findById(id)).thenReturn(Optional.of(fileAudit));

        fileAuditService.updateDT(id);

        verify(fileAuditRepository, times(1)).save(fileAudit);
        assertNotNull(fileAudit.getLast_status_time());
    }

    @Test
    void testUpdateScanResults() {
        Long id = 1L;
        String results = "Scan successful";
        FileAudit fileAudit = new FileAudit();
        fileAudit.setId(id);

        when(fileAuditRepository.findById(id)).thenReturn(Optional.of(fileAudit));

        fileAuditService.updateScanResults(id, results);

        verify(fileAuditRepository, times(1)).save(fileAudit);
        assertEquals(results, fileAudit.getScanResults());
    }

    @Test
    void testFindByAnalysisId_ValidID() throws AnalysisIdNotFoundException {
        String analysisId = "123";
        FileAudit fileAudit = new FileAudit();
        fileAudit.setAnalysisId(analysisId);

        when(fileAuditRepository.findByanalysisId(analysisId)).thenReturn(List.of(fileAudit));

        List<FileAudit> results = Collections.singletonList(fileAuditService.findByAnalysisId(analysisId));

        assertNotNull(results);
        assertEquals(1, results.size());
        assertEquals(analysisId, results.get(0).getAnalysisId());
    }
    @Test
    void testFindByAnalysisId_InvalidID(){
        String invalidAnalysisId = "InvalidId";
        assertThrows(AnalysisIdNotFoundException.class, () -> {
            fileAuditService.findByAnalysisId(invalidAnalysisId);
        });
    }
    @Test
    void testFindBySHA256_NotNull() {
        String sha256 = "abcdef123456";
        FileAudit fileAudit = new FileAudit();
        fileAudit.setSHA256(sha256);

        when(fileAuditRepository.findBySHA256(sha256)).thenReturn(List.of(fileAudit));

        List<FileAudit> results = Collections.singletonList(fileAuditService.findBySHA256(sha256));

        assertNotNull(results);
        assertEquals(1, results.size());
        assertEquals(sha256, results.get(0).getSHA256());
    }

    @Test
    void testFindBySHA256_Null(){
        // Given
        String sha256 = "nonexistentSHA256";
        // When
        FileAudit foundAudit = fileAuditService.findBySHA256(sha256);
        // Then
        assertNull(foundAudit);
        foundAudit = null;
        assertNull(foundAudit);
    }
    @Test
    void testPreviousScanResults() {
        Long id = 1L;
        String results = "Previous scan results";
        FileAudit fileAudit = new FileAudit();
        fileAudit.setId(id);
        fileAudit.setScanResults(results);

        when(fileAuditRepository.findById(id)).thenReturn(Optional.of(fileAudit));

        String result = fileAuditService.PreviousScanResults(id);

        assertNotNull(result);
        assertEquals(results, result);
    }
}