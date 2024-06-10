package com.fscan.File.Scanner.serviceImplementation;

import com.fscan.File.Scanner.APIconnector.VirusTotal;
import com.fscan.File.Scanner.FileAuditDTO.FileAuditDTO;
import com.fscan.File.Scanner.entity.FileAudit;
import com.fscan.File.Scanner.exception.AnalysisIdNotFoundException;
import com.fscan.File.Scanner.exception.FileAccessException;
import com.fscan.File.Scanner.exception.ScanningUnderProgressException;
import com.fscan.File.Scanner.service.FileAuditService;
import com.fscan.File.Scanner.service.FileControllerService;
import com.fscan.File.Scanner.utils.Validators;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class FileControllerServiceImpl implements FileControllerService {


    @Autowired
    private FileAuditService fileAuditService;

    @Autowired
    private VirusTotal virusTotal;

    @Autowired
    private Validators validators;


    public ResponseEntity<String> FileHandlerService(MultipartFile file) throws FileAccessException, ScanningUnderProgressException {
        FileAuditDTO fileAuditDTO = fileAuditService.save(file.getOriginalFilename(), "File uploaded to DB");
        Long id  = fileAuditDTO.getId();


        String scanResponse = virusTotal.ScanByFile(file,fileAuditService,id);

        if(validators.isValidResult(scanResponse)){

            String scanResults = validators.FinalizeVerdict(scanResponse);
            fileAuditService.updateScanResults(id,scanResults);
            fileAuditService.updateDT(id);

            return new ResponseEntity<>(scanResults, HttpStatus.ACCEPTED);
        }

        return new ResponseEntity<>(scanResponse,HttpStatus.ACCEPTED);
    }

    @Override
    public ResponseEntity<String> AnalysisIdHandlerService(String id) throws AnalysisIdNotFoundException, ScanningUnderProgressException {

        FileAudit fileAuditDTO = fileAuditService.findByAnalysisId(id);
        Long uid  = fileAuditDTO.getId();

        String scanResponse = virusTotal.ScanByAnalysisId(id,fileAuditService,uid);
        if(validators.isValidResult(scanResponse)){
            String scanResults = validators.FinalizeVerdict(scanResponse);

            fileAuditService.updateScanResults(uid,scanResults);
            fileAuditService.updateDT(uid);

            return new ResponseEntity<>(scanResults,HttpStatus.ACCEPTED);
        }
        return new ResponseEntity<>(scanResponse,HttpStatus.ACCEPTED);

    }
}
