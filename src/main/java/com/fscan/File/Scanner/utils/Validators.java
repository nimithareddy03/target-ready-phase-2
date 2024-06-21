package com.fscan.File.Scanner.utils;


import com.fscan.File.Scanner.exception.ScanningUnderProgressException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import java.util.Iterator;
import java.util.Objects;

@Component
public class Validators {
    @Autowired
    private EvalJSON evalJSON;
    public boolean IsAnalyisId(String analysisId){

        int len = analysisId.length();

        return len==60 && analysisId.charAt(len - 1) == '=' && analysisId.charAt(len - 2) == '=';

    }

    public boolean IsValidResponse(String response) {

        String status = evalJSON.Status(response);
        return Objects.equals(status, "completed");
    }

    /*
        scanResponse =
            {
                "malicious": 0,
                "type-unsupported": 15,
                "failure": 0,
                "undetected": 58,
                "suspicious": 0,
                "confirmed-timeout": 0,
                "harmless": 0,
                "timeout": 0
             }
    */

    public boolean isValidResult(String result) throws ScanningUnderProgressException {
        if(result.contains("malicious") &&
                result.contains("undetected") &&
                result.contains("harmless") &&
                result.contains("suspicious"))
        {
            System.out.println(result);
            JSONObject entireStats = evalJSON.TextToJSON(result);

            Iterator<String> keys = entireStats.keys();
            while (keys.hasNext()){
                String field = keys.next();
                String value = entireStats.get(field).toString();
                if( Integer.parseInt(value) >0){
                    return true;
                }
            }
            throw new ScanningUnderProgressException();
        }

        return false;
    }

    public String FinalizeVerdict(String result){
        JSONObject stats = evalJSON.TextToJSON(result);
        int maliciousCount = (int) stats.get("malicious");
        int suspiciousCount = (int) stats.get("suspicious");
        if(maliciousCount > 0){
            return "Malicious";
        }

        if(suspiciousCount > 0){
            return "Suspicious";
        }
        return "No Malware Found";
    }


}
