package com.fscan.File.Scanner.service;

import com.fscan.File.Scanner.exception.AnalysisIdNotFoundException;
import com.fscan.File.Scanner.exception.FileAccessException;
import com.fscan.File.Scanner.exception.ScanningUnderProgressException;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public interface FileControllerService {

    ResponseEntity<String> FileHandlerService(MultipartFile file) throws FileAccessException, ScanningUnderProgressException;
    ResponseEntity<String> AnalysisIdHandlerService(String id) throws AnalysisIdNotFoundException, ScanningUnderProgressException;
}
