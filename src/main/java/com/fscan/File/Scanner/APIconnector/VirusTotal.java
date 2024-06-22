package com.fscan.File.Scanner.APIconnector;


import com.fscan.File.Scanner.exception.FileAccessException;
import com.fscan.File.Scanner.exception.ScanningUnderProgressException;
import com.fscan.File.Scanner.service.FileAuditService;
import com.fscan.File.Scanner.utils.Validators;
import com.fscan.File.Scanner.utils.EvalJSON;
import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import com.google.common.io.ByteSource;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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

    private static final String scanHex,scanId,upload;
    private static final String apiKey = System.getenv("API-KEY");
    private final Logger log = LoggerFactory.getLogger(VirusTotal.class);

    @Autowired
    private Validators validators;

    @Autowired
    private EvalJSON evalJSON;

    private final RestTemplate restTemplate = new RestTemplate();;
    static {
        ResourceBundle rb = ResourceBundle.getBundle("api-config");
        // store the name of the implementation clas in a static variable
        scanHex = rb.getString("url-scan-hex");
        scanId = rb.getString("url-scan-id");
        upload = rb.getString("url-upload");
    }

    String ShaGenerator(byte[] fileContents) throws IOException {
        ByteSource byteSource = ByteSource.wrap(fileContents);
        HashCode hashCode = byteSource.hash(Hashing.sha256());
        return hashCode.toString();
    }

    String ScanByHex(String hex_code)  {
        //After one Client Response, the MultiPart-file
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
            return "{\"" +
                        "code" +
                    "\":\"" +
                        "NotFoundError" +
                    "\"}"; // Return the Error so that it can be converted to JSON.
        }
    }

    String UploadFile(MultipartFile multipartFile) throws FileAccessException {

        byte[] fileBytes= null;
        try {
            fileBytes = multipartFile.getBytes();
        } catch (IOException e) {
            log.warn("Error in reading Multipart contents.");
            throw new FileAccessException("in uploading file");
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

        String responseForAnalysisId = response.getBody();
        if(validators.IsValidResponse(responseForAnalysisId)){
            JSONObject detailedResult  = new JSONObject();

            String result = evalJSON.StatsByAId(response.getBody());
            String verdict = validators.FinalizeVerdict(result);

            detailedResult.append("Verdict",verdict);

            if(verdict.equals("Malicious")||verdict.equals("Suspicious")){
                JSONObject malwareType = evalJSON.MalwareDetailsFromAnalysisIdResponse(responseForAnalysisId);
                detailedResult.append("MalwareType",malwareType);
            }

            //Updating the Audit Date base
            fileAuditService.updateStatus(id,"Scanning Completed(using analysis_id)");
            fileAuditService.updateScanResults(id,verdict);
            fileAuditService.updateDT(id);

            return detailedResult.toString();
        }

        //Since the Status of the uploaded file is queued for Scanning
        fileAuditService.updateStatus(id,"Queued at Virus Total Database");
        fileAuditService.updateDT(id);

        return "Please try again after some time";// even for error

    }

    public String ScanByFile(MultipartFile file,FileAuditService fileAuditService,Long id) throws FileAccessException, ScanningUnderProgressException {

        String originalFileName = file.getOriginalFilename();
        String name = file.getName();
        String contentType = file.getContentType();
        byte[] content = new byte[0];
        try {
            content = file.getBytes();
        } catch (IOException e) {
            throw new FileAccessException("unable to read multipart file");
        }

        String hexCode = "00";
        try {
            hexCode = this.ShaGenerator(content);
        } catch (IOException ignored) {
                // unable to generate hex code can be ignored so that file will be sent to uploading.
        }

        if(hexCode.equals("00")){
            fileAuditService.updateStatus(id,"Unable to Calculate Hex,Uploading in progress.");
            fileAuditService.updateDT(id);
        }
        else{
            fileAuditService.updateSHA256(id,hexCode);
            fileAuditService.updateStatus(id,"Scanning Using SHA256");
            fileAuditService.updateDT(id);
        }



        String responseForHexScan ="{}";
        try{
            responseForHexScan = this.ScanByHex(hexCode);
        }
        catch (Exception e){
            log.warn("Error in Scanning using hash Value");//any exception other than FileNotFound. The application uploades the file to VT db.
        }

        String result = evalJSON.analysisStats(responseForHexScan);
        //any error in getting results by using HEXcode
        //result will be either a proper stats(Malicious, Suspicious, No Malware found)
        // or Not foundError (if hex code is not present in DB).
        if(!Objects.equals(result, "NotFoundError")){
            try {
                if(validators.isValidResult(result)){
                    JSONObject detailedResult = new JSONObject();

                    String verdict = validators.FinalizeVerdict(result);
                    detailedResult.append("Verdict",verdict);

                    if(verdict.equals("Malicious")||verdict.equals("Suspicious")){
                        JSONObject malwareType = evalJSON.MalwareDetailsFromHexResponse(responseForHexScan);
                        detailedResult.append("MalwareType",malwareType);
                    }

                    fileAuditService.updateStatus(id,"Scanning Completed(using SHA256)");
                    fileAuditService.updateScanResults(id,verdict);
                    fileAuditService.updateDT(id);

                    return detailedResult.toString();//if found in Database.
                }
            } catch (ScanningUnderProgressException e) {
                fileAuditService.updateStatus(id,"User tried to fetch response without using analysis Id(immediately)");
                fileAuditService.updateDT(id);
                throw new ScanningUnderProgressException();
            }
        }


        MultipartFile mockMultipartFile = new MockMultipartFile(name,originalFileName, contentType, content);
        // initial file will be available for GC as one request is made(Scan by hex-code)
        // so creating a multipart file.

        String analysis_id = this.UploadFile(mockMultipartFile);//Getting Analysis ID from VT

        if(validators.IsAnalyisId(analysis_id)){
            //we received a proper analysis_id
            fileAuditService.updateStatus(id,"File uploaded to Virus Total Database");
            fileAuditService.updateAID(id,analysis_id);
            fileAuditService.updateDT(id);
            return "File uploaded to Virus Total DataBase" +
                    " with analysis ID: \n " + analysis_id;

        }
        return analysis_id;
        //any error while
        //uploading the file,return the error message as String.

    }
}
