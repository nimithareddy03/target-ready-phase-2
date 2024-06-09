package com.fscan.File.Scanner.APIconnector;


import com.fscan.File.Scanner.entity.FileAudit;
import com.fscan.File.Scanner.service.FileAuditService;
import com.fscan.File.Scanner.utils.Validators;
import com.fscan.File.Scanner.utils.evalJSON;
import com.fscan.File.Scanner.utils.sha256;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.util.Objects;
import java.util.ResourceBundle;

@Component
public class VirusTotal {

    private static final String apiKey,scanHex,scanId,upload;
    private final Logger log = LoggerFactory.getLogger(VirusTotal.class);

    private final RestTemplate restTemplate = new RestTemplate();;
    static {
        ResourceBundle rb = ResourceBundle.getBundle("api-config");
        // store the name of the implementation clas in a static variable
        apiKey = rb.getString("api-key");
        scanHex = rb.getString("url-scan-hex");
        scanId = rb.getString("url-scan-id");
        upload = rb.getString("url-upload");
    }


    private String ScanByHex(String hex_code)  {
        //After one Client Response the MultiPart-file
        // will be removed from our temp database which cases an error in uploading the file
        log.info("Scanning using HEX");
        String url = scanHex + hex_code;

        HttpHeaders headers = new HttpHeaders();
        headers.set("x-apikey", apiKey);
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        ResponseEntity<String> response = null;
        try{
            response = restTemplate.exchange(url, HttpMethod.GET, requestEntity,String.class);
            return response.getBody();

        }catch (HttpClientErrorException.NotFound e){
            log.info("received an error While scanning using Hex"+e);
            return "{\"code\":\"NotFoundError\"}"; // Return the Error so that it can be converted to JSON.
        }



    }

    private String UploadFile(MultipartFile multipartFile)  {

        byte[] fileBytes= null;
        try {
            fileBytes = multipartFile.getBytes();
        } catch (IOException e) {
            log.warn("Error in reading Multipart contents.");
            return "Unable to read multipart file.";
        }
        //generating Headers
        HttpHeaders headers = new HttpHeaders();
        headers.set("x-apikey", apiKey);
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new ByteArrayResource(fileBytes) {
            @Override
            public String getFilename() {
                return multipartFile.getName();
            }
        });

        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);

        //getting Response.
        ResponseEntity<String> response = restTemplate.postForEntity(upload, requestEntity, String.class);

        return evalJSON.analysisId(response.getBody());//Sending the Response to extract analysis Id.

    }

    public String ScanByAnalysisId(String analysisID, FileAuditService fileAuditService, Long id){

        String url = scanId + analysisID;
        fileAuditService.updateStatus(id,"Scanning using AnalysisID");
        fileAuditService.updateDT(id);


        HttpHeaders headers = new HttpHeaders();
        headers.set("x-apikey", apiKey);

        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, requestEntity,String.class);


        if(Validators.IsValidResponse(response.getBody())){

            //Updating the Audit Date base
            fileAuditService.updateStatus(id,"Scanning Completed(using analysis_id)");
            fileAuditService.updateDT(id);

            return evalJSON.StatsByAId(response.getBody());
        }

        //Since the Status of the uploaded file is queued for Scanning
        fileAuditService.updateStatus(id,"Queued at Virus Total Database");
        fileAuditService.updateDT(id);

        return "Please try again after some time";// even for error

    }

    public String ScanByFile(MultipartFile file,FileAuditService fileAuditService,Long id){
        String originalFileName = file.getOriginalFilename();
        String name = file.getName();
        String contentType = file.getContentType();
        byte[] content = new byte[0];
        try {
            content = file.getBytes();
        } catch (IOException e) {
            return "Unable to read multipart file";
        }

        String hexCode = sha256.generate(file);
        if(hexCode.equals("00")){//unable to generate SHA256 for given file.
            return "unable to generate SHA256 for given file.";
        }

        //When user tries to upload same file again fetching the result using hex will lead to exhaustion of QUOTA.
        //if the ScanResults of the corresponding file are present in the audit table. then it can be displayed.
        //if The ScanResults are not present in the audit Table i.e. analysis id is
        // generated but user didn't use the other controller to get ScanResults then use the analysisId to generate Results


        FileAudit savedFileAudit = null;
        try{
            savedFileAudit = fileAuditService.findBySHA256(hexCode);
            Long previousScanId  = savedFileAudit.getId();
            String previousScanResults = fileAuditService.PreviousScanResults(previousScanId);
            log.info("file present in fileScanner database.");
            if(previousScanResults.isEmpty()){

                log.info("User didn't fetch the response using Analysis Id");

                String previousScanAnalysisId = savedFileAudit.getAnalysisId();
                fileAuditService.findByAnalysisId(previousScanAnalysisId);
                fileAuditService.updateStatus(id,"Displayed previous Analysis id to User");
                fileAuditService.updateDT(id);

                return "Please get the results using Analysis id: " + previousScanAnalysisId;
            }

            fileAuditService.updateStatus(id,"Used previous scan results to Get the malicious status");
            fileAuditService.updateDT(id);

            return previousScanResults;

        }catch (NullPointerException ex){

            //Updating Status and time in DB.
            fileAuditService.updateSHA256(id,hexCode);
            fileAuditService.updateStatus(id,"Scanning Using SHA256");
            fileAuditService.updateDT(id);
        }

        String responseForHexScan ="NotFoundError";
        try{
            responseForHexScan = this.ScanByHex(hexCode);
        }
        catch (Exception e){
            log.warn("Error in Scanning using hash Value");//any exception other than FileNotFound. The application uploades the file to VT db.
        }

        String result = evalJSON.analysisStats(responseForHexScan);//any error in

        //get results by using HEXcode
        //result will be either a proper stats(malicious,harmless,undetected)
        // or Not foundError (if hex code is not present in DB).
        if(!Objects.equals(result, "NotFoundError")){
            fileAuditService.updateStatus(id,"Scanning Completed(using SHA256)");
            fileAuditService.updateDT(id);
            return result;//if found in Database.
        }


        MultipartFile mockMultipartFile = new MockMultipartFile(name,originalFileName, contentType, content);
        // initial file will be available for GC as one request is made(Scan by hex-code)
        // so creating a multipart file.

        String analysis_id = this.UploadFile(mockMultipartFile);//Getting Analysis ID from VT
        if(Validators.IsAnalyisId(analysis_id)){
            //we received a proper analysis_id
            fileAuditService.updateStatus(id,"File uploaded to Virus Total Database");
            fileAuditService.updateAID(id,analysis_id);
            fileAuditService.updateDT(id);
            return "File uploaded to Virus Total DataBase" +
                    " with analysis ID: \n " +analysis_id;

        }
        return analysis_id;
        //any error while
        //uploading the file,return the error message as String.


    }
}
